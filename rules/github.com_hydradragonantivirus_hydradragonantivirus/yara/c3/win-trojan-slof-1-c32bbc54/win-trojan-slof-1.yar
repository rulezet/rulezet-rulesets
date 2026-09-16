rule Win_Trojan_Slof_1
{
strings:
	$a0 = { e0cd2180fce075d68cd9890e1901890e1d01890e2101909090b82135cd21891e10018c0612018ec1bb4000b44acd21 }


condition:
	$a0
}