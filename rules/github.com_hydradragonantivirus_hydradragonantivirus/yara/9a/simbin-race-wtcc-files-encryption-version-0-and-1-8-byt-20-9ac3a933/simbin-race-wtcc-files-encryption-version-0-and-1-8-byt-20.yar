rule Simbin_Race_WTCC_files_encryption_version_0_and_1__8_byt_20_
{
strings:
	$a0 = { 4617802d13e42f2f276f1e1923656914412c0105 }

condition:
	$a0
}