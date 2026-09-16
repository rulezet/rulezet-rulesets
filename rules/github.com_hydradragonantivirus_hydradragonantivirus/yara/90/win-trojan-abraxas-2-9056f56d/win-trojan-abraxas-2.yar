rule Win_Trojan_Abraxas_2
{
strings:
	$a0 = { 3c33c9ba9e00cd21b74093ba0001b9b004cd21c3b4 }


condition:
	$a0
}