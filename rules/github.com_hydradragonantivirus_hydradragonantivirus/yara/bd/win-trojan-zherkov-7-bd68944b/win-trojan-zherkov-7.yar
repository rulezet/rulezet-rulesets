rule Win_Trojan_Zherkov_7
{
strings:
	$a0 = { 2e300547e2fab8dd4bcd213d34127503 }


condition:
	$a0
}