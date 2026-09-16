rule Win_Trojan_NoLimit_1
{
strings:
	$a0 = { 408d5604b90c00cd21b4408d96bb01b9ab01cd21b800429933c9cd21b4408d965201b90400cd21 }


condition:
	$a0
}