rule Win_Trojan_Gift_1
{
strings:
	$a0 = { b854464947cd21663d454e4f447438061e8cc8488ed8812e0300f00f40030603008ec0be000133 }


condition:
	$a0
}