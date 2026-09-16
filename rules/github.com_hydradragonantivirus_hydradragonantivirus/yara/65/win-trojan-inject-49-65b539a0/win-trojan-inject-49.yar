rule Win_Trojan_Inject_49
{
strings:
	$a0 = { 494e46[0-24]55504446494c45256c75 }

	$a1 = { 6d73646f776e6c642e746d70 }

	$a2 = { 70617061636b2e657865 }


condition:
	$a0 and $a1 and $a2
}