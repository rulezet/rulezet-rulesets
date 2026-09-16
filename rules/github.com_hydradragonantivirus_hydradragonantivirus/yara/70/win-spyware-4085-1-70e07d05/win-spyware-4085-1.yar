rule Win_Spyware_4085_1
{
strings:
	$a0 = { 2e67616d616e69612e636f6d0025 }

	$a1 = { 0a0000005c776e766473662e61780000 }


condition:
	$a0 and $a1
}