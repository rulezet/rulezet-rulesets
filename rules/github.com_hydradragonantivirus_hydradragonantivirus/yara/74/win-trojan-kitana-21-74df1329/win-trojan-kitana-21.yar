rule Win_Trojan_Kitana_21
{
strings:
	$a0 = { 87de2eff0e????cd12b98a00d3c88ec00e1f33fff3a4fd8745aa[0-1]ab8d45a6[0-1]8745ac[0-1]abcd19407503 }


condition:
	$a0
}