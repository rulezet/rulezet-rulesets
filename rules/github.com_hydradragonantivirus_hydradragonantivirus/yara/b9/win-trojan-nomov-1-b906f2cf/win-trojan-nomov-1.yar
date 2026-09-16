rule Win_Trojan_Nomov_1
{
strings:
	$a0 = { 0583e907cd215850cd21935850fec4fec492e8da002d1b009283e913cd21585087f2813c0e58 }


condition:
	$a0
}