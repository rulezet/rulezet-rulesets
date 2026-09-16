rule Win_Trojan_Yafo_1
{
strings:
	$a0 = { bf8000b98000fcf3a4c3b8023dcd2172538bd8b90300 }


condition:
	$a0
}