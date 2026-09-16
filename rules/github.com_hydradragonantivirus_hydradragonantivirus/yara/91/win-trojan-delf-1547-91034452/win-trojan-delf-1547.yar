rule Win_Trojan_Delf_1547
{
strings:
	$a0 = { 85c00f8463020000686cbd48006aff6a00e898b2f7ff8bd885db741ee8e5b3f7ff3db7000000751253e848b2f7ff6a00e8d1b2f7ffe94d020000 }


condition:
	$a0
}