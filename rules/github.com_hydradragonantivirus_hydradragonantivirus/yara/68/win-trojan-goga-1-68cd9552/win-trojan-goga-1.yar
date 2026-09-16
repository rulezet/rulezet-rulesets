rule Win_Trojan_Goga_1
{
strings:
	$a0 = { 21eb258b1e800633c933d2b80242cd21d1e8d1ea73 }


condition:
	$a0
}