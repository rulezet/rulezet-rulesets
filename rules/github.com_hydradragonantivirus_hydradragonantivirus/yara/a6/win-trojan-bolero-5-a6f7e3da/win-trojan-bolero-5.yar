rule Win_Trojan_Bolero_5
{
strings:
	$a0 = { 0790e81702eb08905b599df99c5153cfb013cd21e89601cf511e525083fb01741db42ccd2180 }


condition:
	$a0
}