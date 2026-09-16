rule Win_Trojan_SillyRC_43
{
strings:
	$a0 = { 02012bc13b44017416b440cd74b8004233c9cd74b4408d54ff }


condition:
	$a0
}