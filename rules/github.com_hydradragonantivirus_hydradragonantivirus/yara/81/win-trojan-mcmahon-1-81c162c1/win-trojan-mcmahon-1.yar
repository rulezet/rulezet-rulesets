rule Win_Trojan_Mcmahon_1
{
strings:
	$a0 = { f901c6864c0501b440b91b058d960501cd21e8af01b440b91c008d965105cd21e89301b43ecd21 }


condition:
	$a0
}