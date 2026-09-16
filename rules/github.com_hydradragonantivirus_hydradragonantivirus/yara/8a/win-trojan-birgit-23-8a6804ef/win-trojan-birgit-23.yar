rule Win_Trojan_Birgit_23
{
strings:
	$a0 = { e2fdba1702ffd2c353baff01ffd25bb440b91701ba0001cd2153baff01ffd25bc3 }


condition:
	$a0
}