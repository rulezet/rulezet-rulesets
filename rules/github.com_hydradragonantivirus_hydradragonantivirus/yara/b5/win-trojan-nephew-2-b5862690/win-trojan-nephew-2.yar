rule Win_Trojan_Nephew_2
{
strings:
	$a0 = { 8ec0be2f0f0e1fbff004b90600f3a48b1e7a108b0e7c1032e49af004000043e2f89d5f5e07 }


condition:
	$a0
}