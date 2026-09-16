rule Win_Trojan__0256_0006_001_1
{
strings:
	$a0 = { b9890526300547e2fab440b9b105bab106cd21c3b8014333c9cd21b441cd21c3546865204c617a }


condition:
	$a0
}