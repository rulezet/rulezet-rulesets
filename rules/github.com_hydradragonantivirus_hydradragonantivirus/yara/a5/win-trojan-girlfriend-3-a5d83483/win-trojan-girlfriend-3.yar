rule Win_Trojan_GirlFriend_3
{
strings:
	$a0 = { 558bec83c4f053b890934700e8bfd3f8ff8b1dfcb247008b[0-96]426f79467269656e64 }


condition:
	$a0
}