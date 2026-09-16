rule Win_Trojan_Frodolives_1
{
strings:
	$a0 = { e800005e83ee0356f8b8fefecd2172??8cd8488ec0 }


condition:
	$a0
}