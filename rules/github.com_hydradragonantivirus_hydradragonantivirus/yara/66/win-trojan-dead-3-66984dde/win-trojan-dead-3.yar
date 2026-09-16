rule Win_Trojan_Dead_3
{
strings:
	$a0 = { 1e06e87e01735ee8cb010e0732c0b9b40090bf5e0590fcf3aae801010706b44abbffffe8220253 }


condition:
	$a0
}