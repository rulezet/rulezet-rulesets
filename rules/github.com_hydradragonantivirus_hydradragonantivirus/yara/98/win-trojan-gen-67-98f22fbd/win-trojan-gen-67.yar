rule Win_Trojan_Gen_67
{
strings:
	$a0 = { 3eef0187742a962d0200c6060001e9a30101b43ffec450ba0301b9ec00cd21b8004233c999cd21 }


condition:
	$a0
}