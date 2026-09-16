rule Win_Trojan_Level3_5
{
strings:
	$a0 = { 9f863977b8183e29d2093108f215d131be52aee6e966ea400a1e469d9bebc4 }


condition:
	$a0
}