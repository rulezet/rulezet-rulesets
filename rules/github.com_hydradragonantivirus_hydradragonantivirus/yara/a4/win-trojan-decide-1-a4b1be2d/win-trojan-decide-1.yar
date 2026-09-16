rule Win_Trojan_Decide_1
{
strings:
	$a0 = { 3fb90400ba00f0cd21b43ecd212ea102f03ddead7403eb }


condition:
	$a0
}