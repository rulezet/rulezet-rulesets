rule Win_Trojan_Small_4488
{
strings:
	$a0 = { 48747848746648745448744248743048740733c0 }


condition:
	$a0
}