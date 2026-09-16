rule Win_Trojan__1487_0006_000_1
{
strings:
	$a0 = { 26894515b440b9a701baab029c2eff1e9d0233c026894515b440b90300290ea202baa1029c2e }


condition:
	$a0
}