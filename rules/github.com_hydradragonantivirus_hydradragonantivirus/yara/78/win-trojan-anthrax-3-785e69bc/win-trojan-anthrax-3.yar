rule Win_Trojan_Anthrax_3
{
strings:
	$a0 = { b104d3e88cd903c1ba0b00eb71b8d0 }


condition:
	$a0
}