rule Win_Trojan_Polimer_1
{
strings:
	$a0 = { 6c018cd80500108ed8b440cd21 }


condition:
	$a0
}