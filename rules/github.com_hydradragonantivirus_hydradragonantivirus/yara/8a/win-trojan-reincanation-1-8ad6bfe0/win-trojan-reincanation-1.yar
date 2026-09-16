rule Win_Trojan_Reincanation_1
{
strings:
	$a0 = { cd21b93a01b440ba0001cd219933c9b80157cd21b43ecd21b42acd2180fe04751380fa1575 }


condition:
	$a0
}