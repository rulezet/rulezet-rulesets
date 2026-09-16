rule Win_Trojan_Globe_1
{
strings:
	$a0 = { 57b80100509a3612c6009a4602c600bfc4001e57bf98031e57b8411f50bfda221e579a21 }


condition:
	$a0
}