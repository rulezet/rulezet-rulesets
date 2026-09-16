rule Win_Trojan_Ck_1
{
strings:
	$a0 = { b700ba0001b440cd21598b1609018eda33d2b440cd210e1fb99600ba9800b80157cd210e1f }


condition:
	$a0
}