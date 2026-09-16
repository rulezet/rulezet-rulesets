rule Win_Trojan_Inst_1
{
strings:
	$a0 = { 645f4279746520209a00005100c8000100bf6e011e578dbe00ff16576a009a680b51009a36 }


condition:
	$a0
}