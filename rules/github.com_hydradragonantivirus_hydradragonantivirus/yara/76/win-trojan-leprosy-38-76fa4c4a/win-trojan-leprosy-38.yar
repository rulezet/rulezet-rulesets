rule Win_Trojan_Leprosy_38
{
strings:
	$a0 = { 018a2f320e0201882f4381fb5f047ef159c3ba00018b1ee40153e8e0ff5bb92803b440cd21 }


condition:
	$a0
}