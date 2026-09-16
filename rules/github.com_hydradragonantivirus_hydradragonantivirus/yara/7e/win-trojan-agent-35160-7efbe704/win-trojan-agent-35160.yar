rule Win_Trojan_Agent_35160
{
strings:
	$a0 = { e7e01ae75f3aa5bf5a67c27dd0768129e5af922dd841fc6baf6e04e78a7becd1e578b14ecfef2a1a2133dce933b42131db0b3144ce91eb26b366090829690e6493e708572a21f20ce4bbb2 }


condition:
	$a0
}