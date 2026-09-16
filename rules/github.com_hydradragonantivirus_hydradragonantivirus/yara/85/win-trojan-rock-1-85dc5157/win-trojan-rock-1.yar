rule Win_Trojan_Rock_1
{
strings:
	$a0 = { ff207506c646ff01eb04c646ff008a46ff89ec5dcb5589e55dcb1e526f636b52616e646f6d }


condition:
	$a0
}