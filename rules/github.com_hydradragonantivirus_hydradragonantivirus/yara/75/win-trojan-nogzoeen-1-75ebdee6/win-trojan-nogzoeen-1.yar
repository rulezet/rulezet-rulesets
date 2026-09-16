rule Win_Trojan_Nogzoeen_1
{
strings:
	$a0 = { 02be0e00bf1c001e07e86600be1000bfb6001e07e85b00bfb600be1200e85a00bfb600be1400 }


condition:
	$a0
}