rule Win_Trojan_Dust_1
{
strings:
	$a0 = { 3d4e44744cc3b8023dba9e00cd2193b80057cd215251b440b9c901ba0001cd21b80157595a }


condition:
	$a0
}