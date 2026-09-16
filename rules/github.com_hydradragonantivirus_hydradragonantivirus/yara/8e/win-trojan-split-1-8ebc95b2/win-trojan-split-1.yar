rule Win_Trojan_Split_1
{
strings:
	$a0 = { b0028d962102cd218bd8b43fb904008dbedf018bd7cd }


condition:
	$a0
}