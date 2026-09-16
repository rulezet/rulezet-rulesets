rule Win_Trojan_Mybot_5921
{
strings:
	$a0 = { 6e40e65def15573a3dfc1724fd91b178d4fb1b716bc867d067c3c9a31e32adee78562a1178c6f6f9a039559ce5b5a46ace9a8b760b5650 }


condition:
	$a0
}