rule Win_Trojan_IronMaiden_2
{
strings:
	$a0 = { 25cd215f0e1f8b855702a300018aa5590288260201b41a }


condition:
	$a0
}