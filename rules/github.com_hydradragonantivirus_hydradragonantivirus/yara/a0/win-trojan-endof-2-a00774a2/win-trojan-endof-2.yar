rule Win_Trojan_EndOf_2
{
strings:
	$a0 = { b104d3e8bbff0f03d8391e030072118b1e03004040 }


condition:
	$a0
}