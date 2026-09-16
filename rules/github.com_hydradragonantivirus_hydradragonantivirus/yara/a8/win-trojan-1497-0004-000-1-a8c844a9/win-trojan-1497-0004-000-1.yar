rule Win_Trojan__1497_0004_000_1
{
strings:
	$a0 = { b466cf5a1febf6ba8000cd66c3b440cd21c3e86b01ba0006b90006e8efffc3b4422bc92bd2 }


condition:
	$a0
}