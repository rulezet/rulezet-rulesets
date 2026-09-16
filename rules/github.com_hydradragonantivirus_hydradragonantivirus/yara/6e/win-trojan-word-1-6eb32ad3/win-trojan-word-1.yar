rule Win_Trojan_Word_1
{
strings:
	$a0 = { 3d4230750c81f96719750681fb917674 }


condition:
	$a0
}