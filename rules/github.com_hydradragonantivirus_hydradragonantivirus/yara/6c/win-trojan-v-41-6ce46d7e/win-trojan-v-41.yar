rule Win_Trojan_V_41
{
strings:
	$a0 = { d2754d3d00fa7748c1e80440c1e0048bd050b80042cd21b440cd21b4400e1fba0001b97e01 }


condition:
	$a0
}