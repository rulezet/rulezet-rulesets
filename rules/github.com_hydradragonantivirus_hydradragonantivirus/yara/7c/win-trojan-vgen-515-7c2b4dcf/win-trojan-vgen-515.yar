rule Win_Trojan_VGEN_515
{
strings:
	$a0 = { 5e83ee0356f8b8fefecd21722c8cd8488ec026832e030023832e0200238e0602001e0e1f33ffb98101f3a4b021 }


condition:
	$a0
}