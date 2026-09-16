rule Win_Trojan_Metallica_2
{
strings:
	$a0 = { 06002d000126a30000c3b443b000cd2181e1fe00b443b001cd21c3b80103ba8000b90100cd13 }


condition:
	$a0
}