rule Win_Trojan__0053_0001_002_1
{
strings:
	$a0 = { 33c933d2cd21b4408d967604b90300cd21a1960024e00c0ca39600e848000633c08ec0faa1 }


condition:
	$a0
}