rule Win_Trojan_V_34
{
strings:
	$a0 = { 8bfe350000b810010ac0500ac01e0622c00e0e0ae4071f0ae4b99d0a22e42bce22e4d1e90bc0d1e923c0 }


condition:
	$a0
}