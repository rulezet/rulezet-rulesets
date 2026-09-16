rule Win_Trojan_Vgen_22
{
strings:
	$a0 = { cd213d00ba7509be00018cc88ed8eb462e8b260e018cc02e030610018ed08cc02e03061401502eff361201cbb8 }


condition:
	$a0
}