rule Win_Trojan_Jouce_1
{
strings:
	$a0 = { bea806462e8a04f6d034532e8804e2f3b8ff020e07bba906b90100ba8000cd13b80019cd21 }


condition:
	$a0
}