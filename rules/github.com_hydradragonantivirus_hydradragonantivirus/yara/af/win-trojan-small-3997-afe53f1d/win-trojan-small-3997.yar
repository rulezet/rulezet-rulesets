rule Win_Trojan_Small_3997
{
strings:
	$a0 = { 31ed81c5cbac14f881c535653408558d9de8f2afff81c3341250 }


condition:
	$a0
}