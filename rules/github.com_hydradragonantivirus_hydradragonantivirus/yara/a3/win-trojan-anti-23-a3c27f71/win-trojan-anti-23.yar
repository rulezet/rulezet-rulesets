rule Win_Trojan_Anti_23
{
strings:
	$a0 = { 2c4675636b210831393939206d61799a000047005589e5e899fde857fee811ff5d31c09a1601 }


condition:
	$a0
}