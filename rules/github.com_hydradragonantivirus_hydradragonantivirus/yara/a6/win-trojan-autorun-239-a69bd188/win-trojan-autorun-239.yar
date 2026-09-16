rule Win_Trojan_Autorun_239
{
strings:
	$a0 = { 494e464e414e }

	$a1 = { 5452656d6f7661626c65447269766544 }

	$a2 = { 3648696b747a7b786f7574469c5854564826255526737a }


condition:
	$a0 and $a1 and $a2
}