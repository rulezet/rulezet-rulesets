rule Win_Spyware_Goldun_107
{
strings:
	$a0 = { 618c6d6361666565139081b095471d32f676b20f6176700772 }


condition:
	$a0
}