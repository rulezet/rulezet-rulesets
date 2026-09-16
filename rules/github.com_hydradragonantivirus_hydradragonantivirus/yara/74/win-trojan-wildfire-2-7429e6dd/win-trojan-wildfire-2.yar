rule Win_Trojan_WildFire_2
{
strings:
	$a0 = { 751281fb7373750c2e803ea701377504b4739dcf9d }


condition:
	$a0
}