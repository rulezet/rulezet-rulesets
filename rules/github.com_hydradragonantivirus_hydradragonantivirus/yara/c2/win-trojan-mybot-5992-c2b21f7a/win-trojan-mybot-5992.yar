rule Win_Trojan_Mybot_5992
{
strings:
	$a0 = { 6b415b0f02b482061d99da53af25a7df88228268e7c62cce75cd2abb72cd3ade41bd1a6ce26a612bb9ce4d28967329cd569692c9e587e48c7175ee5017612b1b5cfabceac0ea39d4bfd1d405542f665ebf5a }


condition:
	$a0
}