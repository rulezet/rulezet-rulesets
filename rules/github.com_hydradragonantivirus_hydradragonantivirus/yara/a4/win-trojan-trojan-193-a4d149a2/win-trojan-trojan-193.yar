rule Win_Trojan_Trojan_193
{
strings:
	$a0 = { fa8bd7c3b440b90405ba0001eb52 }


condition:
	$a0
}