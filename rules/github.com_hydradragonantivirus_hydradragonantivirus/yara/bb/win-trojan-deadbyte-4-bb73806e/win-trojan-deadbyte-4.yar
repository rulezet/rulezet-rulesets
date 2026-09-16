rule Win_Trojan_DeadByte_4
{
strings:
	$a0 = { 33c09e9f80c43e508b0e3d01ba0001cd21b8024233c933d2cd21588b0e4101ba0005cd21b43e }


condition:
	$a0
}