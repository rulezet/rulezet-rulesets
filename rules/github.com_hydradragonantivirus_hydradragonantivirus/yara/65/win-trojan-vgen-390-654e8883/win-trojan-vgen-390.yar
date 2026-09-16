rule Win_Trojan_VGEN_390
{
strings:
	$a0 = { c604202eff06b404e80200f9c33c307c233c397f1f80bda000207418b00f57b9030081efa20051b90300f3ab81 }


condition:
	$a0
}