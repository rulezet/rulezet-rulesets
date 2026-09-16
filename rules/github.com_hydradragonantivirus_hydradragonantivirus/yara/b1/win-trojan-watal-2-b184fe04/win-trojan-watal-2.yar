rule Win_Trojan_Watal_2
{
strings:
	$a0 = { 40636f7079202f7920253020[0-7]5c7363726970742e696e69 }

	$a1 = { 24312d2c3629203d3d20317370616d3129 }


condition:
	$a0 and $a1
}