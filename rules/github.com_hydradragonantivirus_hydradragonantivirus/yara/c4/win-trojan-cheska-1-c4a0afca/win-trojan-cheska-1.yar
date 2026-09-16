rule Win_Trojan_Cheska_1
{
strings:
	$a0 = { 9a00006e005589e5bfeb040e57bf5a001e57b8ff00509a9f066e00b42ccd2188365800bf5a001e57e8aefa803e58001e }


condition:
	$a0
}