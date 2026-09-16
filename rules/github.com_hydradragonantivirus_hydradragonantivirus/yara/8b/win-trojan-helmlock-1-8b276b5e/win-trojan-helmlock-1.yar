rule Win_Trojan_Helmlock_1
{
strings:
	$a0 = { 832e130408cd12b106d3e08ec033c0cd1332f6b904000ad27805b90400b60033dbb80702cd13 }


condition:
	$a0
}