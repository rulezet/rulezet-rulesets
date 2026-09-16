rule Win_Trojan_Yctc_1
{
strings:
	$a0 = { 0e1fb8ac4bcd213d4bac74 }


condition:
	$a0
}