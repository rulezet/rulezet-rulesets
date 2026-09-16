rule Win_Trojan_Small_4152
{
strings:
	$a0 = { 55e80500000012ed26697281c73965a15e81ef3965a15e }


condition:
	$a0
}