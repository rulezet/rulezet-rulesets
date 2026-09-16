rule Win_Trojan_Angela_1
{
strings:
	$a0 = { 8edaa106008ed8b9ffff8bf2813cf3a5740646e2f7 }


condition:
	$a0
}