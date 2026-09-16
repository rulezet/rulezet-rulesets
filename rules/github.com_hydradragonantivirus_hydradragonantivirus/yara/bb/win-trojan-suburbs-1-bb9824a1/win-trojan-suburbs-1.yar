rule Win_Trojan_Suburbs_1
{
strings:
	$a0 = { 1e068cdfb820008ed8833e000000754a8edf33c08ec0bf8400268b05268b5d028b36010181c6ef012e89042e895c }


condition:
	$a0
}