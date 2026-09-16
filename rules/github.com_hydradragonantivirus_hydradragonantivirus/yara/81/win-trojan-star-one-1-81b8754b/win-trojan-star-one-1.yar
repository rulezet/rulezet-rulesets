rule Win_Trojan_Star_One_1
{
strings:
	$a0 = { 2d03002e8986d600b4408d5604b9de00cd21b80042e8dbff }


condition:
	$a0
}