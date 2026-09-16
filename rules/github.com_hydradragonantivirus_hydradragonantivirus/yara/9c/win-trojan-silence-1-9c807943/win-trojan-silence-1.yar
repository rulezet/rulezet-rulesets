rule Win_Trojan_Silence_1
{
strings:
	$a0 = { 4459b9ec01be1401b41a28244680c43be2f8 }


condition:
	$a0
}