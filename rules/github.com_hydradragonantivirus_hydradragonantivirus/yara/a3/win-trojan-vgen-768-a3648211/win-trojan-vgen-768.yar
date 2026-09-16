rule Win_Trojan_VGEN_768
{
strings:
	$a0 = { 06e87901735ae8c5010e0732c0b9b400bf5405fcf3aae8fe000706b44abbffffe81e0253e836015b8cc85a522bc2 }


condition:
	$a0
}