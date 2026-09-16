rule Win_Trojan_Abraxas_7
{
strings:
	$a0 = { 3c33c9ba9e00cd21b74093ba0001b9c304cd21c3b43bbabe01cd21c3 }


condition:
	$a0
}