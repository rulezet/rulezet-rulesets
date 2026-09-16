rule Win_Trojan_Nephew_3
{
strings:
	$a0 = { 8ec0be310f0e1fbff004b90600f3a48b1e7c108b0e7e1032e49af004000043e2f89d5f5e07 }


condition:
	$a0
}