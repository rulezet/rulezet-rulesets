rule Win_Trojan_RedAlert_2
{
strings:
	$a0 = { 6d70736e09404543484f204f46460472656d200363642003633a5c5589e5b808029acd02 }


condition:
	$a0
}