rule Win_Trojan_Bancos_694
{
strings:
	$a0 = { 9fe39f3bd2fc8a16f5c3cb4c19f03808c5428d2fd3368a412cbeeb1a3387a87a1cd60facd7df16ef352618e30200230468977605ec2ca1d9d0cee89d0706efefc1c179c1f4b21cb805ff24eb }


condition:
	$a0
}