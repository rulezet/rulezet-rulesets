rule Win_Trojan_Opa_7
{
strings:
	$a0 = { 80fc4b74052eff2e1b011e529c2eff1e1b015a1fb8013dcd2193b4400e1fba0001b95a00cd21 }


condition:
	$a0
}