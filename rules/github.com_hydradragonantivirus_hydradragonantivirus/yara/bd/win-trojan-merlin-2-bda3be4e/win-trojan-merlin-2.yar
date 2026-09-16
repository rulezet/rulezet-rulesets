rule Win_Trojan_Merlin_2
{
strings:
	$a0 = { b3e28d76112e281cd0c346e2f8f0e443a76329d99f6b6305265ce83eedf17d1c4cfb7de6fa80439a45bae238809a55b0a484d88592 }


condition:
	$a0
}