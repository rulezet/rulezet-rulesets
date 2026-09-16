rule Win_Trojan_Viper_1
{
strings:
	$a0 = { 1d00e95001003d8b1e530253e810005b90b99a02ba0001b440cd21e80100c3bb34 }


condition:
	$a0
}