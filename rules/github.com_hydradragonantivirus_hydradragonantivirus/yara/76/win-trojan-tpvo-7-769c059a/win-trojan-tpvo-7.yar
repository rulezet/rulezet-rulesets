rule Win_Trojan_TPVO_7
{
strings:
	$a0 = { 0500ba9204b440e8b1007227baac04268b451126894515a38f04b99c04b440e89900720f5833d2 }


condition:
	$a0
}