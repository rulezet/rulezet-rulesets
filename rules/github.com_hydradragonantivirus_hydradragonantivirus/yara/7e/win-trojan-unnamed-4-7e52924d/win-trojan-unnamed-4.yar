rule Win_Trojan_Unnamed_4
{
strings:
	$a0 = { fafe8bae320281c5030133f6e80000e800005d8b9e2402b440cd21b801578b9e24028b8e28028b }


condition:
	$a0
}