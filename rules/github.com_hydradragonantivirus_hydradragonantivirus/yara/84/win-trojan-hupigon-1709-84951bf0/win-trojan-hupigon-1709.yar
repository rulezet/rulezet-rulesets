rule Win_Trojan_Hupigon_1709
{
strings:
	$a0 = { e803000000eb10ffc3ffffeb0ae840ffff????ffffffffe95b0100008db5????ffff8b0683f8010f844b020000c706010000008bd58b85????ffff2bd08995????ffff0195????ffff8db5????ffff01168b368bfd606a40680010000068001000006a00 }


condition:
	$a0
}