rule Win_Trojan_OnlineGames_35
{
strings:
	$a0 = { 413a5c007e544d50343335322e544d50 }

	$a1 = { 5c52756e4f6e6365 }

	$a2 = { 3138746866672e657865 }


condition:
	$a0 and $a1 and $a2
}