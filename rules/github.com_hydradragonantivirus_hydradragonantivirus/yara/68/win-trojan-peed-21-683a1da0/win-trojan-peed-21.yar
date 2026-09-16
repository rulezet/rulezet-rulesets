rule Win_Trojan_Peed_21
{
strings:
	$a0 = { c1e910c1e910eb1e5589e5b89a????0433450801d089c1c9c2080089eb81c3 }


condition:
	$a0
}