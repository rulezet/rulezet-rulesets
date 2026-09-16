rule Win_Trojan_Trojan_315
{
strings:
	$a0 = { 562d750d26813e8601314c75048c }


condition:
	$a0
}