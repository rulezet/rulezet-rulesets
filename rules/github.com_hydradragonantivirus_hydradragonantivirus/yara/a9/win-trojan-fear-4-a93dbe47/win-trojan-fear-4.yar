rule Win_Trojan_Fear_4
{
strings:
	$a0 = { ea83ea108cd903caba27015152cbfcbf000106570e1fbec202a4a550ba }


condition:
	$a0
}