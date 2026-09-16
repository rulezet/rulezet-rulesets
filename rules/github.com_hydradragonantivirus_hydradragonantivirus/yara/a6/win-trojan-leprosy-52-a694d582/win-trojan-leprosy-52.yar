rule Win_Trojan_Leprosy_52
{
strings:
	$a0 = { 8a073206030188074381fbce037ef1c3 }


condition:
	$a0
}