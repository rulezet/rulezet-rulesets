rule Win_Trojan_Dref_4
{
strings:
	$a0 = { 68c01740009c60e940f8ffff50e800000000ff25303040 }

	$a1 = { 496e736f6d6e69612e61736d }


condition:
	$a0 and $a1
}