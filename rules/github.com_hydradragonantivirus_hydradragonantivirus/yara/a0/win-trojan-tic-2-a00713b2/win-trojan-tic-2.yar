rule Win_Trojan_Tic_2
{
strings:
	$a0 = { 06b43ecd21b44f0e1fcd21b91efe72288bd1b8023d }


condition:
	$a0
}