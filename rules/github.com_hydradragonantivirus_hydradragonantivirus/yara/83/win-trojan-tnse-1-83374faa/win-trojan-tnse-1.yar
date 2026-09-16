rule Win_Trojan_TNSE_1
{
strings:
	$a0 = { 60061e8b2e03018dbe1f0157b9b20089fead90909090abe2f8c3b86642cd2181fb66427422b820008ec033 }


condition:
	$a0
}