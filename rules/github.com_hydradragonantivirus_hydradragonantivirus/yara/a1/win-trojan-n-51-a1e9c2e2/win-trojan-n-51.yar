rule Win_Trojan_N_51
{
strings:
	$a0 = { 5657505351521e062bff579de83500c4064c002e89843b022e8c843d02c406 }


condition:
	$a0
}