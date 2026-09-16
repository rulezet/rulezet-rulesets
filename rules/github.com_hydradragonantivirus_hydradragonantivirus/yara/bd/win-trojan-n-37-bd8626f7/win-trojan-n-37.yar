rule Win_Trojan_N_37
{
strings:
	$a0 = { daa106008ed8b9ffff8bf2813cf3a5740646e2f7eb }


condition:
	$a0
}