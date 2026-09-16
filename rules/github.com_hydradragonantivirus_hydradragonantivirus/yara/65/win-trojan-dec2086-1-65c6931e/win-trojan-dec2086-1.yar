rule Win_Trojan_DEC2086_1
{
strings:
	$a0 = { 4c4874d53d504b74d03d524174cb0761c32ec6864f0800b84456cd2181fa4c53750c81f94d4175 }


condition:
	$a0
}