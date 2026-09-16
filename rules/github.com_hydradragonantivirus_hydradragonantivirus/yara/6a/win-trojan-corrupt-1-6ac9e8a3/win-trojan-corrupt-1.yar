rule Win_Trojan_Corrupt_1
{
strings:
	$a0 = { 90b419cd213c0074063c017402eb7dbe5d02b800b88ec0bf0000b9a402e80000565750535152e35b8bd733c0fcac3c }


condition:
	$a0
}