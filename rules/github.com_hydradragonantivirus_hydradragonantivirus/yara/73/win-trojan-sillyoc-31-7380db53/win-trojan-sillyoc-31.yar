rule Win_Trojan_SillyOC_31
{
strings:
	$a0 = { 2f01b44ecd21721eba9e00b443cd21b8023d0ac8cd21bb014393cd21b9fa04b440ba0001cd21b4 }


condition:
	$a0
}