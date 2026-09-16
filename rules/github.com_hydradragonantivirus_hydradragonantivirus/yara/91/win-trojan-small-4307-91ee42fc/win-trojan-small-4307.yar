rule Win_Trojan_Small_4307
{
strings:
	$a0 = { 6a046a006a0068fffffbffff1584104700 }


condition:
	$a0
}