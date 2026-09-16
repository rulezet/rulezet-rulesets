rule Win_Trojan_Cascade_3
{
strings:
	$a0 = { 0400ba7a05b43fcd217227a17a05 }


condition:
	$a0
}