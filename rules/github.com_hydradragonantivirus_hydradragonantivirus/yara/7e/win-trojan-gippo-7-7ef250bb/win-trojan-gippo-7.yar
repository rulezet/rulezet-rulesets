rule Win_Trojan_Gippo_7
{
strings:
	$a0 = { 10002bd181c18503b440cd215888269403b900218b16b7 }


condition:
	$a0
}