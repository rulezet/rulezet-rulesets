rule Win_Trojan_Nazgul_II_1
{
strings:
	$a0 = { c6c4c381c68f6405cdb4fbbf60fb7f005659760081c2e0d38be803f529e2fc31dbfb81ebe01cd1cb4ef089c5 }


condition:
	$a0
}