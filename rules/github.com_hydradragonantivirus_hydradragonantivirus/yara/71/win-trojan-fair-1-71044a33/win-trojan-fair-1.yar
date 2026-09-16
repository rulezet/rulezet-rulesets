rule Win_Trojan_Fair_1
{
strings:
	$a0 = { 803e4c0500c333c0e80300eb0e902e8f06870560061e2eff2687051e0e1f061e9c2ec60689050033c08ed82e }


condition:
	$a0
}