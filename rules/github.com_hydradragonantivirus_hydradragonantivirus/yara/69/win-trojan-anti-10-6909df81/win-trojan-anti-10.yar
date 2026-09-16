rule Win_Trojan_Anti_10
{
strings:
	$a0 = { ba00010e1fb4402e8b1e7003cd21b8024233c933d2 }


condition:
	$a0
}