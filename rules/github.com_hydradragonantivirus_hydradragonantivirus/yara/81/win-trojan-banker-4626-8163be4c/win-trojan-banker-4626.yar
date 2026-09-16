rule Win_Trojan_Banker_4626
{
strings:
	$a0 = { 558bec83c4f053b8a4cd4800e8f74f00008b1dd80549[0-98]43616978612045636f6ef46d696361 }


condition:
	$a0
}