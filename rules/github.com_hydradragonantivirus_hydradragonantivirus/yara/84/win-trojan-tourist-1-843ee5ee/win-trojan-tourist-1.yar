rule Win_Trojan_Tourist_1
{
strings:
	$a0 = { 4d0253b80125ba3f019003d3cd215b53b803258bd381c2 }


condition:
	$a0
}