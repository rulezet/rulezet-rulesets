rule Win_Trojan_ProtoVirus_1
{
strings:
	$a0 = { 80fc307403e9c50081fe39307403e9bc00be31d49dcf }


condition:
	$a0
}