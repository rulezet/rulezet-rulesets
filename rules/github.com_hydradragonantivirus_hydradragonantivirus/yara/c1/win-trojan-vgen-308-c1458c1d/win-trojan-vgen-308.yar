rule Win_Trojan_VGEN_308
{
strings:
	$a0 = { 8b2d81ed06018cd80510002e0186ee012e0186f0011e0e0e1f07b83452bb3452cd133bc17503e9a000b801028d }


condition:
	$a0
}