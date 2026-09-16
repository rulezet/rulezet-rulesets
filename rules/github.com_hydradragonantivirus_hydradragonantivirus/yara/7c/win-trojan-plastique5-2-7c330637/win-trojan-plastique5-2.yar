rule Win_Trojan_Plastique5_2
{
strings:
	$a0 = { 404bcd213d78567513072e8e165600 }


condition:
	$a0
}