rule Win_Trojan_VGEN_30
{
strings:
	$a0 = { ffb8024ab702cd2f47bb06007435e8ddfff3a4511fff37be9a028c0f8777feb28187cf569cb80204cd019cff1e4c }


condition:
	$a0
}