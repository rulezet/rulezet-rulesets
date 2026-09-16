rule Win_Trojan_Roman_1
{
strings:
	$a0 = { 8a04e80f002e8804494683f90075f061fbeb1a90525350 }


condition:
	$a0
}