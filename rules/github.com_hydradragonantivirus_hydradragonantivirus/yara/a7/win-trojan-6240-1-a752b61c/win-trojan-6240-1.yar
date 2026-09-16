rule Win_Trojan_6240_1
{
strings:
	$a0 = { 0300755ebfe4001e57bff2011e57b8ff00509a26098b00bf44001e57bff2011e579a6d0c }


condition:
	$a0
}