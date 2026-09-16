rule Win_Trojan_Something_2
{
strings:
	$a0 = { 8e1e8303b43fcd21725f3d00e873 }


condition:
	$a0
}