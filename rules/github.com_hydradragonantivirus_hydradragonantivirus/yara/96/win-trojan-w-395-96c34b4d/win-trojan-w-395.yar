rule Win_Trojan_W_395
{
strings:
	$a0 = { 15691c333825b9ffffbfd11c2df44d46bdb41aeb0c8bf2f6142ff9b1b50fb7f3e922ffffff7200610020006f006d002000440069 }


condition:
	$a0
}