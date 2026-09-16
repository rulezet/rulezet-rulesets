rule Win_Trojan_Aids_1
{
strings:
	$a0 = { fab08f5b53b9a100300743e2fbc3 }


condition:
	$a0
}