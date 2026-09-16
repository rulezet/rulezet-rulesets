rule Win_Trojan_Creeper_3
{
strings:
	$a0 = { c6fec60e07cd27502d004b7425583d }


condition:
	$a0
}