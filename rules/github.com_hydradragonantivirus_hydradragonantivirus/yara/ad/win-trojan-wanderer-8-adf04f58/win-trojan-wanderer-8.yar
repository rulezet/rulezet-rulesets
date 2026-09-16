rule Win_Trojan_Wanderer_8
{
strings:
	$a0 = { 1e6a04813e9300dcac7465b44abbffffcd2181eb0110725880c710b44acd21b448bb000090cd21 }


condition:
	$a0
}