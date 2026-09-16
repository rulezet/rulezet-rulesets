rule Win_Trojan_Multiple_1
{
strings:
	$a0 = { 36ff842604e8fb008d94ce03cd21e9ebfee8a700b42acd2180fa05750ab002b9000199cd26ebfe }


condition:
	$a0
}