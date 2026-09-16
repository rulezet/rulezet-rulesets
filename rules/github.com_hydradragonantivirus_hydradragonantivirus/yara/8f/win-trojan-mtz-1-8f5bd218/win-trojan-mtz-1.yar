rule Win_Trojan_MTZ_1
{
strings:
	$a0 = { 5e595b311c46e201c375f8942b4c2b042abc2a742a2c2ae4299c2954290c28c4287c283428ec27a4275c271426 }


condition:
	$a0
}