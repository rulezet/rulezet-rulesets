rule Win_Trojan_VGEN_769
{
strings:
	$a0 = { 5d81ed0b01b4fecd21fec47452b800b08ec08ed833ff89feabad400e1f7503b801b805c9078ec050508db60001 }


condition:
	$a0
}