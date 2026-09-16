rule Win_Trojan_BOO_5
{
strings:
	$a0 = { 617ca113044848a31304b106d3e08ec050b8250350b83002a34c008c064e00b9ff03900e1fbe00 }


condition:
	$a0
}