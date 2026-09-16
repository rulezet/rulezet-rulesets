rule Win_Trojan_MAD_4
{
strings:
	$a0 = { 8ac60495ff2d88852806e721fcaff9a9e7c6fab732daaaaf05a9b78dc2aae7b8faaf25a9b78a15aa }


condition:
	$a0
}