rule Win_Trojan_DeadByte_2
{
strings:
	$a0 = { 33c09e9f80c43e508b0e3601ba0001cd21b8024233c933d2cd21588b0e3a01ba0005cd21b43e }


condition:
	$a0
}