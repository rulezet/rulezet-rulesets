rule Win_Trojan_Sirius_12
{
strings:
	$a0 = { e80200eb108b96c402b9ab02d1e931144646e2fac38db62602bf0001fca4a506b82435cd212e8c06f0fa2e89 }


condition:
	$a0
}