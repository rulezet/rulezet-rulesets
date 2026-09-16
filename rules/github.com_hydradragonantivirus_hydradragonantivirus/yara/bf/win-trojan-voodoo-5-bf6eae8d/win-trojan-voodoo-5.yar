rule Win_Trojan_Voodoo_5
{
strings:
	$a0 = { 57b80100509ad80650009a91025000bf7e191e57bf7e011e57b890105031c050509ac307 }


condition:
	$a0
}