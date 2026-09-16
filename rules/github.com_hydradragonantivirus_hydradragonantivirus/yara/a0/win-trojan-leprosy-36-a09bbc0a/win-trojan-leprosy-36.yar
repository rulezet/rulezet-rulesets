rule Win_Trojan_Leprosy_36
{
strings:
	$a0 = { 0301882f4381fb58047ef159c3ba00018b1ee50153e8e0ff5bb92003b440cd2153 }


condition:
	$a0
}