rule Win_Trojan_MTZ_2
{
strings:
	$a0 = { b503da4c36ddc137b9c2c5344867bdc44035177084f16a8a69c98c5fc4395cc7e46953e716e55464916a88967d2f41 }


condition:
	$a0
}