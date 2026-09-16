rule Win_Trojan_Faulkner_1
{
strings:
	$a0 = { c3b42acd213c027512b409baeb01cd21b80200b93200fa99cd26fbc3b43dba9e00cd2193c3 }


condition:
	$a0
}