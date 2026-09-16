rule Win_Trojan_Crew_3
{
strings:
	$a0 = { 8904b4408bd781c20301b9af07cd21 }


condition:
	$a0
}