rule Win_Trojan_ZMT_1
{
strings:
	$a0 = { 050001898457ffb440b9fc008bd6cd21 }


condition:
	$a0
}