rule Win_Trojan_Sinowal_49
{
strings:
	$a0 = { 558bec51ff7508e8d258ffff8b4d0c8b018b50188b4020a338ad[0-34]45fc6862ab01005151515150 }


condition:
	$a0
}