rule Win_Trojan_Mecdon_1
{
strings:
	$a0 = { 1800ba130103d5e8cefe33c933d2b80242e8c4fe53e885feb9be05ba000103d55bb440e8b2 }


condition:
	$a0
}