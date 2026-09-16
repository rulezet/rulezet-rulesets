rule Win_Trojan_Yozis_2
{
strings:
	$a0 = { 0a76696374696d2e77726974656c696e6520766963636f64650d }


condition:
	$a0
}