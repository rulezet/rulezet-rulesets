rule Win_Trojan_Vacsina_1
{
strings:
	$a0 = { e800005b2e8947fbb800008ec026a1c5 }


condition:
	$a0
}