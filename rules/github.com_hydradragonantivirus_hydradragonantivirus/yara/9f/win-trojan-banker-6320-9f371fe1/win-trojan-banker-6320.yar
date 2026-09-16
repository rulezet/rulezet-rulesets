rule Win_Trojan_Banker_6320
{
strings:
	$a0 = { 558bec83c4f053b8cc534900e8c706f7ff8b1d90884900 }

	$a1 = { 43616978612045636f6ec3b46d696361204665646572616c }


condition:
	$a0 and $a1
}