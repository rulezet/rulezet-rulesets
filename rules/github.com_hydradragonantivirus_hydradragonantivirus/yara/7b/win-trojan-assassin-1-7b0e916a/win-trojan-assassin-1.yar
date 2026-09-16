rule Win_Trojan_Assassin_1
{
strings:
	$a0 = { ff4545c43e8107268b7b7ea4a575f21f5d582eff3683075053b82012cd2f268a1db81612cd2f }


condition:
	$a0
}