rule Win_Trojan_Memorial_1
{
strings:
	$a0 = { bd00??????b9500500008db52e000000038d290000008a852d000000 }


condition:
	$a0
}