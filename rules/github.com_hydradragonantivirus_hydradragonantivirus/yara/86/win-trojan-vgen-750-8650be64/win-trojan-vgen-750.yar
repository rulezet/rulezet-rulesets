rule Win_Trojan_VGEN_750
{
strings:
	$a0 = { ff8bf78b5c16b450cd21b9ff0051ff742c0e1ff3a48c061f00eb00ea21000000b95200f3a48cc8488ed9be4c00a5a5 }


condition:
	$a0
}