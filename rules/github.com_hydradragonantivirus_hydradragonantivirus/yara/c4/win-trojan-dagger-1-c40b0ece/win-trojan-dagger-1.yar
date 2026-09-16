rule Win_Trojan_Dagger_1
{
strings:
	$a0 = { 028acb8af7b280bb8a03cd13b90b0033f68bf9bbde002e8a20d0cc2e88a58a034683c704e2f0 }


condition:
	$a0
}