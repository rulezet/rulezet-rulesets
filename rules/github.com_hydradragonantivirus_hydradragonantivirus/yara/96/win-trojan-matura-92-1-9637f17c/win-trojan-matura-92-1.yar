rule Win_Trojan_Matura_92_1
{
strings:
	$a0 = { 750c3ce17504b83412cf0ac074102e8a265f069e2e8a265e06 }


condition:
	$a0
}