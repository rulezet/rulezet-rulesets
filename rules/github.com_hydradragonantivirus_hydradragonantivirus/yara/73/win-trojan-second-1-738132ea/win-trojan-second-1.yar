rule Win_Trojan_Second_1
{
strings:
	$a0 = { 018b4706538bd8b440b93402cd21b9ffff5b2b4f0a81e93802894f0a8bd383c20a8b470653 }


condition:
	$a0
}