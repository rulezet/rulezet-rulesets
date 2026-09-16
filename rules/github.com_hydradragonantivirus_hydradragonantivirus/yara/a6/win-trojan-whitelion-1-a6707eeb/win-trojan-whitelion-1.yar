rule Win_Trojan_WhiteLion_1
{
strings:
	$a0 = { d2b4ffcd2180feff7503e997008bc5488ed8a10300b93b }


condition:
	$a0
}