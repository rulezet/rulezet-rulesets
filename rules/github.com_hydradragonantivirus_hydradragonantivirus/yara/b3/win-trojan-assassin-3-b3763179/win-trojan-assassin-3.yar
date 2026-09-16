rule Win_Trojan_Assassin_3
{
strings:
	$a0 = { ffbb1e00b9c9120e1fd1e98137193783c302e2f7 }


condition:
	$a0
}