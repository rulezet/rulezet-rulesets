rule Win_Trojan_Peed_209
{
strings:
	$a0 = { 558bec83ec1c535657 }

	$a1 = { 8945f08b45f08b4dec8b04818b4df803018b4df08b55ec89048a }


condition:
	$a0 and $a1
}