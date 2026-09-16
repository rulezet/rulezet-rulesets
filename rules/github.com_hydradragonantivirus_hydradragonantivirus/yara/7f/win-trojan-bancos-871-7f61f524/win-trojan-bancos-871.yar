rule Win_Trojan_Bancos_871
{
strings:
	$a0 = { b4f5ba2553fda905133b7fda6a5cb636fb3f057225942f3d3fda46ae44f45d4c869e0e597414b535b2c2e8acd088f2c2a9babef9cbf59d2a5fcc321a0e13a35104 }


condition:
	$a0
}