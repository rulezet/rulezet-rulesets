rule Win_Trojan_VGEN_348
{
strings:
	$a0 = { 9a00000b019a0000a9005589e59a9f050b01c6063aa000c706de9f5f20c606e19f19b02150bfe09f1e579a0b007700a0 }


condition:
	$a0
}