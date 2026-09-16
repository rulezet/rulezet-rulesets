rule Win_Trojan_Grunt_9
{
strings:
	$a0 = { eb22e819008d9e3b01403e8b960e03b9ea0087dbf7d0311783c302e2f7c3 }


condition:
	$a0
}