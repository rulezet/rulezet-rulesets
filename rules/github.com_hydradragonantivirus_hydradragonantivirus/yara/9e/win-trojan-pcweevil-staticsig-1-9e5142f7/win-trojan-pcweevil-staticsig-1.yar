rule Win_Trojan_Pcweevil_staticsig_1
{
strings:
	$a0 = { e3f4659626fcc35f30cd5aff5c2be55edaecc2af278d9aaaa795d32b }


condition:
	$a0
}