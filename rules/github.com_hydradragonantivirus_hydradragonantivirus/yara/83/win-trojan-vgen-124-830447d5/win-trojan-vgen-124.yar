rule Win_Trojan_Vgen_124
{
strings:
	$a0 = { 5d81ed03018db6a501bf0001a5a58d96a901b41acd21b44e33c98d969b01cd21726ab8023d8d96c701cd2193b4 }


condition:
	$a0
}