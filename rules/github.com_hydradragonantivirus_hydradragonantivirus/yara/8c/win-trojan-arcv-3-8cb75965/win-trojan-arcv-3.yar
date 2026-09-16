rule Win_Trojan_ARCV_3
{
strings:
	$a0 = { be1601b9????bf1601fcad05????abe2f9 }


condition:
	$a0
}