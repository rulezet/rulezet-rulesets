rule Win_Trojan_DirFiller_1
{
strings:
	$a0 = { 5e83ee0353511e0633c01e501fa1fc01403d25007407ff06fc01e9bf001f1e0e0e1f07b80102bb860503deba80 }


condition:
	$a0
}