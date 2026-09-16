rule Win_Trojan_Companion_18
{
strings:
	$a0 = { 01b409cd2133c0cd16e88b01eb008a26a701cd2180fd0f759beb00b0ade664eb00b13f8ac1e6 }


condition:
	$a0
}