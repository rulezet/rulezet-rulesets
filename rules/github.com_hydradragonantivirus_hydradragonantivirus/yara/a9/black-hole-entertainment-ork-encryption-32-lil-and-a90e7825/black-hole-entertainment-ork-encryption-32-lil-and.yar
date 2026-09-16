rule Black_Hole_Entertainment_ORK_encryption__32_lil_AND_
{
strings:
	$a0 = { 3980b148[0-20]3980b148[0-20]3980b148 }

condition:
	$a0
}