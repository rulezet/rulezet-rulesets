rule Win_Trojan_Boot_11
{
strings:
	$a0 = { d88ed0bc007cfbb704b313ff0f8b07b106d3e08ec0fcbe007c33ffb90002f3a406b8680050 }


condition:
	$a0
}