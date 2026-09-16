rule Win_Trojan_Nanjing_1
{
strings:
	$a0 = { e800005b8cc8b91000f7e103c383d2002d800183da00f7f1bb9b015053cb8cd82ea349018cc88ed88ec0ff360206ff }


condition:
	$a0
}