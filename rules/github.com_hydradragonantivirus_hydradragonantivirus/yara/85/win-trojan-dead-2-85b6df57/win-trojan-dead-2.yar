rule Win_Trojan_Dead_2
{
strings:
	$a0 = { 1e06e87901735ae8c5010e0732c0b90c03bf5d05fcf3aae8fe000706b44abbffffe8270253e836015b8cc85a522bc2 }


condition:
	$a0
}