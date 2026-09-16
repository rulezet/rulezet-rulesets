rule Win_Trojan_Trivial_162
{
strings:
	$a0 = { 062c0087cf87fbfec0f2afb8023d87d71e061fcd21931f87d691b440cd21c3 }


condition:
	$a0
}