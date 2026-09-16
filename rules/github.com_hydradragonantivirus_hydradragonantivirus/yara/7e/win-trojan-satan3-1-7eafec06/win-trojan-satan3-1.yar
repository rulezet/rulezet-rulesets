rule Win_Trojan_Satan3_1
{
strings:
	$a0 = { 2e8b0e4c002e8b164e00cd21b404cd1a2e89162200b4402e8b1e4a002e8b0e280033d2cd21 }


condition:
	$a0
}