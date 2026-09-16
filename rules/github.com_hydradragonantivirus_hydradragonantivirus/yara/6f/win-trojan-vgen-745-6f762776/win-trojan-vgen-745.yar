rule Win_Trojan_VGEN_745
{
strings:
	$a0 = { 73e800008bf48b2c81ed07018db60401e88d03b89930cd213bc374558cd8488ed833ff803d5a7549836d033b83 }


condition:
	$a0
}