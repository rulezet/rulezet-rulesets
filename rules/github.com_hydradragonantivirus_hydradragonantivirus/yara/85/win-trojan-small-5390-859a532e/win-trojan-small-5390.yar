rule Win_Trojan_Small_5390
{
strings:
	$a0 = { 5589e5[0-26]e81b000000e821000000030683c604[0-255]685481f48fb8ce6c4200ff10c3 }


condition:
	$a0
}