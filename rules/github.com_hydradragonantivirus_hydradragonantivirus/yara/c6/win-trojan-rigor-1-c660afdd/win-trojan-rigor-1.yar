rule Win_Trojan_Rigor_1
{
strings:
	$a0 = { 2001cd21e8e5ffc3e8d3ff721b515333c933d2b4428b1e1d01cd215a598b1e1d01b440cd21e8c4 }


condition:
	$a0
}