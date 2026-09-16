rule Win_Trojan_MAD_1
{
strings:
	$a0 = { 5d81ed340abf6c0a03fdb9470a2e802dd847e2f9 }


condition:
	$a0
}