rule Win_Trojan_Nutcrack_1
{
strings:
	$a0 = { 214e7574637261636b65722e373435382028706f6c79206d62722f626f6f742f636f6d2f65 }


condition:
	$a0
}