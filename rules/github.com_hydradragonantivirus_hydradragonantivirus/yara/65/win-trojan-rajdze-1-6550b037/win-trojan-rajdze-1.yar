rule Win_Trojan_Rajdze_1
{
strings:
	$a0 = { 5a444a523a416e742d56312e307c25737c25737c25647c545845 }


condition:
	$a0
}