rule Win_Trojan_Onlinegames_30
{
strings:
	$a0 = { e8ebfeffff0bc303c23d52744b2ec3588661f18beec4f61a869e82ec44a000 }


condition:
	$a0
}