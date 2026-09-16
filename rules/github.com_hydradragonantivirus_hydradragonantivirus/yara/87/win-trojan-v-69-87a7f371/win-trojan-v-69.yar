rule Win_Trojan_V_69
{
strings:
	$a0 = { 2bd089165102c6064b0201e87300b000e86500b440b91c00ba4f020e1fcd21eb3190b002e85100 }


condition:
	$a0
}