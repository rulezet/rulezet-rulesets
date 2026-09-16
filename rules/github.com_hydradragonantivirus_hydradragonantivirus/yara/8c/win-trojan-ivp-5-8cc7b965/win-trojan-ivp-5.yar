rule Win_Trojan_IVP_5
{
strings:
	$a0 = { e2fdbae501ffd2c353bacd01ffd25bb440b9e500ba0001cd2153bacd01ffd25bc3 }


condition:
	$a0
}