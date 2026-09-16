rule Win_Trojan_Ieronim_3
{
strings:
	$a0 = { 8ec026c53e0400c605cf26c53e0c00c605cfbb0b0151b89a02b904022e31074343e2f959c3 }


condition:
	$a0
}