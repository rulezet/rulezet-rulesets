rule Win_Trojan_Galt_1
{
strings:
	$a0 = { 81eed704b8ed1dcd213debfe754c90900e1f81c60e0681 }


condition:
	$a0
}