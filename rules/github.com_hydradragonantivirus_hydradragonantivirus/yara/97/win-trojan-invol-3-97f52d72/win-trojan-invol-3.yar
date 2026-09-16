rule Win_Trojan_Invol_3
{
strings:
	$a0 = { 8cc88ed88ec033f68bfefcad33c2abe2 }


condition:
	$a0
}