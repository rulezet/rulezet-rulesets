rule Win_Trojan_Dtran_1
{
strings:
	$a0 = { 04037d0fb8ae0050e870075933c050e8130359e851010bc0740ee84a013d01007406c706ac00 }


condition:
	$a0
}