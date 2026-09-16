rule Win_Trojan_Lineage_99
{
strings:
	$a0 = { ed809a64049321fadcd5541c24654732fc13928bd4f27bb62bbbd11ea5b70c715cd17bcb6003e356e7cc8929b85e087e84eb5206b187ba487f33e3caa9f10eeb61fe1750 }


condition:
	$a0
}