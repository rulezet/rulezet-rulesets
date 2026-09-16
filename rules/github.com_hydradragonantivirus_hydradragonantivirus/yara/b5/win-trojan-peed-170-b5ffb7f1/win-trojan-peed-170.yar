rule Win_Trojan_Peed_170
{
strings:
	$a0 = { bf89a84501ba73e4140071355589e5ff5508c9c204005589e5870203550803550c }


condition:
	$a0
}