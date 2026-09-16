rule Win_Trojan_AT_10
{
strings:
	$a0 = { a4a532c08ec0bf400283ee3a26803d60b195f3a474118e }


condition:
	$a0
}