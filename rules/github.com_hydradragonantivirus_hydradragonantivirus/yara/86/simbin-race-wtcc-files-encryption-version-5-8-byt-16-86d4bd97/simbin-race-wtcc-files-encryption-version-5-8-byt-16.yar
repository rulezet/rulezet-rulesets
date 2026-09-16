rule Simbin_Race_WTCC_files_encryption_version_5__8_byt_16_
{
strings:
	$a0 = { 45133b810ba109962542f0e57d191153 }

condition:
	$a0
}