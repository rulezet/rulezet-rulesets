rule Win_Trojan_Personality_10
{
strings:
	$a0 = { 3b200d0a5753485368656c6c2e52756e2822433a5c464f524d582e62617422 }


condition:
	$a0
}