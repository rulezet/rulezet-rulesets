rule Win_Trojan_VGEN_722
{
strings:
	$a0 = { eb0087c908ed9086db1689db0e86c989c90bc989f687db0bc01786c91e1f1e1f750023c9e8020087db5d87d223db81c5 }


condition:
	$a0
}