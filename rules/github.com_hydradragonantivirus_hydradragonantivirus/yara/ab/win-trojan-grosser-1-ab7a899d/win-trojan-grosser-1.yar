rule Win_Trojan_Grosser_1
{
strings:
	$a0 = { b440ba0001b95f02cd2172c7bf8000be68f290b90001 }


condition:
	$a0
}