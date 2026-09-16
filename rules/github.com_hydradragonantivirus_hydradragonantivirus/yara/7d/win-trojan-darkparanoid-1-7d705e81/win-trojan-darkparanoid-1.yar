rule Win_Trojan_DarkParanoid_1
{
strings:
	$a0 = { bded058bfd8cdd552ec7853bfd00002e8e9d3bfdffb517fa2e8f85c7fdff3606002e8f0679032e8b2e79032e892e }


condition:
	$a0
}