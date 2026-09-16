rule Win_Trojan_IntBiohazard_1
{
strings:
	$a0 = { b9580081340000817402000083c604e2f2c3b801faba4559cd10b419cd2150b410b202cd137303e9ed00b40eb202cd21b44732d2be7102cd21ba2a02b4 }


condition:
	$a0
}