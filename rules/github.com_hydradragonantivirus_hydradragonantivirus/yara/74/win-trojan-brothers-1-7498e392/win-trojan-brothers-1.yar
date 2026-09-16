rule Win_Trojan_Brothers_1
{
strings:
	$a0 = { 1e7c0fb413cd2f1e52b413cd2f5a07eb0590c4164c00 }


condition:
	$a0
}