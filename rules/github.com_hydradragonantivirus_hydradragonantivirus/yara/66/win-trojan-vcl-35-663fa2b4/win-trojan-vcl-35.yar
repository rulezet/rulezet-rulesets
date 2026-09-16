rule Win_Trojan_VCL_35
{
strings:
	$a0 = { 8d5680cd21b44eb91000ba3402cd217227807e951075 }


condition:
	$a0
}