rule Win_Trojan_Autorun_418
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d73797374656d2e7b }

	$a1 = { 7d5c }

	$a2 = { 2e657865 }


condition:
	$a0 and $a1 and $a2
}