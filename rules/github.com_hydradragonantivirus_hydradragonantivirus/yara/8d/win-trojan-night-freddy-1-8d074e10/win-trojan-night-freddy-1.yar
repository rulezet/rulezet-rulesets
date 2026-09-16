rule Win_Trojan_Night_Freddy_1
{
strings:
	$a0 = { 2eff1e0300c3b80103b90100ba8000bb0001cd13b038e670b09de671b078e670b05de671cd20f5 }


condition:
	$a0
}