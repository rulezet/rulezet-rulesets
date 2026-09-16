rule Win_Trojan_Yankee_15
{
strings:
	$a0 = { f3b9e50bf32ea4061f53b82135cd218c }


condition:
	$a0
}