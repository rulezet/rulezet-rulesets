rule Win_Trojan_Virogen_5
{
strings:
	$a0 = { 45cef99045cef99045cef9fcf9bfbc15fb90f5ceccfb90f5ceccfb90f5ceccfb90f5ceccfb90f5ceccfb90f5cecc }


condition:
	$a0
}