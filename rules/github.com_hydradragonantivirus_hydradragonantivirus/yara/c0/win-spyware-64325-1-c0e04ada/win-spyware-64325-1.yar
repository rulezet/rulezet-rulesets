rule Win_Spyware_64325_1
{
strings:
	$a0 = { 6e5c52756e }

	$a1 = { 776f726c646f6677[0-11]2f6c6f67696e7375 }

	$a2 = { 626174746c652e6e65742f6c }

	$a3 = { 696e2e6c6976652e }

	$a4 = { 676c652e636f6d2f616363 }

	$a5 = { 506173737764 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}