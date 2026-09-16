rule Win_Trojan_VGEN_404
{
strings:
	$a0 = { 56565fe800005e83c6575632c9a5a48bd65e4880c44fcd2172368bfeb43ee83000b43fe82400803de974e8b802 }


condition:
	$a0
}