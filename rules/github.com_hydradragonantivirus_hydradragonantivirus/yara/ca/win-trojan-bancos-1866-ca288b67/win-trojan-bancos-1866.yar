rule Win_Trojan_Bancos_1866
{
strings:
	$a0 = { ffdef7e730f99f4c91ab6e096d844d2acc3561ed084cfdf2a2088743a87f19fe1f4de72db798bf9174887a2d4be806aa97aef1c1aca65b3e470da112f6c03d0782fa91627fde }


condition:
	$a0
}