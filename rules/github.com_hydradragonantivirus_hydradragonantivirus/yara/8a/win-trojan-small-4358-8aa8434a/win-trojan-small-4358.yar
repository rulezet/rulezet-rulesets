rule Win_Trojan_Small_4358
{
strings:
	$a0 = { 31db8d837bfef8f905854547065068fc080000 }


condition:
	$a0
}