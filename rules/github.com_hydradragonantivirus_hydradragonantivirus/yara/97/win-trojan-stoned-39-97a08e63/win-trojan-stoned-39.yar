rule Win_Trojan_Stoned_39
{
strings:
	$a0 = { c706fe0155aa2eff2e11002ec606080002b80103bb0002b90700ba8000cd1372d8 }


condition:
	$a0
}