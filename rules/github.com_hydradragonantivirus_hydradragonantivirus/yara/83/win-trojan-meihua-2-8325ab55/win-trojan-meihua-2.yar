rule Win_Trojan_Meihua_2
{
strings:
	$a0 = { 0e1fb440cd215a1f1e5233c98bd1b80042cd210e1fba2906b91c00b440cd212e8b0e01062e }


condition:
	$a0
}