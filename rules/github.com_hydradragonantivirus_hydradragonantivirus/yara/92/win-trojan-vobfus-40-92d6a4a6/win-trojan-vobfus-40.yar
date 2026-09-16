rule Win_Trojan_Vobfus_40
{
strings:
	$a0 = { 656e74696f6e616c6c7900000001000200c852400000000000ffffffffffffffff000000007c534000f0b742 }


condition:
	$a0
}