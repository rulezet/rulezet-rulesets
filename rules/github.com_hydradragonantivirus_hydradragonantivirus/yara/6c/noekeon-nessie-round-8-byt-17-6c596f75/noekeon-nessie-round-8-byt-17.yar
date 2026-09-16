rule Noekeon_Nessie_round__8_byt_17_
{
strings:
	$a0 = { 801b366cd8ab4d9a2f5ebc63c697356ad4 }

condition:
	$a0
}