rule Win_Trojan_Yankee_14
{
strings:
	$a0 = { f3b9980bf32ea4061f53b82135cd218c }


condition:
	$a0
}