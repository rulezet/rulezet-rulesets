rule Win_Trojan_Birgit_28
{
strings:
	$a0 = { e2fdba3202ffd2c353ba1a02ffd25bb440b93201ba0001cd2153ba1a02ffd25bc3 }


condition:
	$a0
}