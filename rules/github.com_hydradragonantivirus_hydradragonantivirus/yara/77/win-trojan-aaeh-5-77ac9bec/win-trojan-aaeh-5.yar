rule Win_Trojan_AAEH_5
{
strings:
	$a0 = { 2d433030302d616169746e69 }

	$a1 = { 75806a00ff75a4e8f02fffff8bc88bd6e8ed2fffffc785e0feffff1500000083bde0feffff47730983a5f4fdffff00eb }


condition:
	$a0 and $a1
}