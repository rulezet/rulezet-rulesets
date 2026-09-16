rule Win_Trojan_SillyE_11
{
strings:
	$a0 = { b800428b1e9903cd21c3b43f8b1e9903cd21c3b4408b1e9903cd21c3b90400d1e2 }


condition:
	$a0
}