rule Win_Trojan_CodeZero_2
{
strings:
	$a0 = { b801578b4c168b5418cd21b43ecd21b8014332ed8a }


condition:
	$a0
}