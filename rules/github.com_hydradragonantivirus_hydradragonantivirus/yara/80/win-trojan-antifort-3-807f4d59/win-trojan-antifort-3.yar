rule Win_Trojan_AntiFort_3
{
strings:
	$a0 = { 05020050ca02005b8d57052e89172e8c4f029c2eff1fc3002e892783c32c8be3585835 }


condition:
	$a0
}