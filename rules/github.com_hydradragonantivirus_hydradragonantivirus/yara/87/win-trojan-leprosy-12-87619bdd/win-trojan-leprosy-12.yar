rule Win_Trojan_Leprosy_12
{
strings:
	$a0 = { 3a018a2f322e0301882f4381fb2bbc7ef159c3ba00018b1ee70153e8deff5bb9f1bab440cd2153 }


condition:
	$a0
}