rule Win_Trojan_Malatinec_1
{
strings:
	$a0 = { 10b904062e80354847e2f9fa48c8b2483d0cc49ec3b47ec345c3a07b9a66e949494d4b49f35848bfbbc4834b8b }


condition:
	$a0
}