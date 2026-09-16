rule Win_Trojan_Agent_32829
{
strings:
	$a0 = { 292be9d3f155362a558eaf8cee55ac6fd07e1b4622e785edbac39d2a6a92ac9084bd772ff6c80d62efbc4eec6e562ef477c37f569dc015607ab5202a81b66d7205 }


condition:
	$a0
}