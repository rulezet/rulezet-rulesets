rule Win_Trojan_VCL_MUT_1
{
strings:
	$a0 = { b9030051e8080059e2f9b8004ccd21b44eb92700ba3101cd217205e81b00730cb44eba3701cd217203e80d00 }


condition:
	$a0
}