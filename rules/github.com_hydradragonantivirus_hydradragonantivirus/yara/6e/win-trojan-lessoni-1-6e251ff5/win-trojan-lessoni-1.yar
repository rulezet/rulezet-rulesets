rule Win_Trojan_LessonI_1
{
strings:
	$a0 = { 8d944a01cd21724c93b43fb90400ba240103d6cd21 }


condition:
	$a0
}