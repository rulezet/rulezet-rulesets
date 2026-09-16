rule Win_Trojan_Bancos_706
{
strings:
	$a0 = { f22681e65ea2f64f38f195b805772a3b7c66a3f6b9f95d24f45a89ae7bdaa2699eecc982483df17977c3fd3a4d17086afc399934bee178af7bfd333e0d512aa656 }


condition:
	$a0
}