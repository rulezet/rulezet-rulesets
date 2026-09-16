rule Win_Trojan_Bv_2
{
strings:
	$a0 = { be15012e816e00370545454e75f51f06375d641938901f243d1356133e92f5f73892edff38aadbaadbaafd8bd70838b95192cd7a3ad2 }


condition:
	$a0
}