rule Win_Trojan_VGEN_763
{
strings:
	$a0 = { e878017359e8c4010e0732c0b9b400bf5205fcf3aae8fd000706b44abbffffe81d0253e835015b8cc85a522bc2 }


condition:
	$a0
}