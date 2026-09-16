rule Win_Trojan_Agent_35476
{
strings:
	$a0 = { e92b00000059e83500000060689c08000059870235 }


condition:
	$a0
}