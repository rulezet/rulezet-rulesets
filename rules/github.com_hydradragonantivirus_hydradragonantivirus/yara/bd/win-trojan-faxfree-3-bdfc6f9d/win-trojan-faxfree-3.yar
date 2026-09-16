rule Win_Trojan_FaxFree_3
{
strings:
	$a0 = { 47002e8a242e32261c002e88244681fe590375ee585ec3 }


condition:
	$a0
}