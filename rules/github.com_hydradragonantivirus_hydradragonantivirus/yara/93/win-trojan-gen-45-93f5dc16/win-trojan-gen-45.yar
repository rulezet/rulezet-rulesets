rule Win_Trojan_Gen_45
{
strings:
	$a0 = { c0cbbe0600ad3d920174dd3d79 }


condition:
	$a0
}