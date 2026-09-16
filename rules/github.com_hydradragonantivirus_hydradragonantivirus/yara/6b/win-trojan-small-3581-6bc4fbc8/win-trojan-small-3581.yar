rule Win_Trojan_Small_3581
{
strings:
	$a0 = { e0800654622389a750dbd4414353ca9845534dc8db960a4ceeb4b0cb6258ce8c5438ab16e6fcb7f0fd804c5658fc0ecf35517252f64d888abf04d354ea9db8d45fb40e95e46db6a6fb162ebb011df4bc }


condition:
	$a0
}