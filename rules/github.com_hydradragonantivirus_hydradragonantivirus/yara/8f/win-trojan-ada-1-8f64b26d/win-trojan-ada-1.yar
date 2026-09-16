rule Win_Trojan_ADA_1
{
strings:
	$a0 = { b4ffcd1372189cbf00012e8b36620303 }


condition:
	$a0
}