rule Win_Trojan_Gen_189
{
strings:
	$a0 = { 6b20796f752121215053515256571e065589e581ec0001b8be018ed89acc015d00bf00000e }


condition:
	$a0
}