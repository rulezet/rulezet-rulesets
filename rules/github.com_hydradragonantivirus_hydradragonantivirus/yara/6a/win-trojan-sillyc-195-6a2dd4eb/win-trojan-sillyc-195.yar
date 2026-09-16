rule Win_Trojan_SillyC_195
{
strings:
	$a0 = { c3c33920073a6ffb8ad90d0e2895be823777a4cc57dab85d136c83983eb326ecf44ed849e8b1a444 }


condition:
	$a0
}