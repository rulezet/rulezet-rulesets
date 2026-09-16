rule Win_Trojan_Imposter_2
{
strings:
	$a0 = { 02005500020000000100510a0000aa000000040000000903 }


condition:
	$a0
}