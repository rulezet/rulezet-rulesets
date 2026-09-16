rule Win_Trojan_MIPT_4
{
strings:
	$a0 = { fecd2180fc007443061e8cdb4b8edb832e030039832e12 }


condition:
	$a0
}