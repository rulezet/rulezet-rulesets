rule Win_Trojan_Maffy_2
{
strings:
	$a0 = { bf00018bf5a4ad86e0ab03dd3bdc720858fbffa678ff }


condition:
	$a0
}