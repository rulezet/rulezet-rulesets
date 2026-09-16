rule Win_Trojan__0683_0008_000_1
{
strings:
	$a0 = { cd17be0003b93900b400accd17e2f9ebcdcd21c30a4e65656420796f752c20447265616d20796f }


condition:
	$a0
}