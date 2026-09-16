rule Win_Trojan_Foma_2
{
strings:
	$a0 = { fc55e8a703e8f3fc1e0e1f897512c7451a0001c74508b0fec685f302008bf70633c08ed8bb0400c43f26ff352e8f }


condition:
	$a0
}