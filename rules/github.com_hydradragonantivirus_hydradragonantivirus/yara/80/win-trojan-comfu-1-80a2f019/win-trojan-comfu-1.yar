rule Win_Trojan_Comfu_1
{
strings:
	$a0 = { 8ec3bb93fbf7d3268b073ac87404e2f7eb1f1e0781eb510353c3 }


condition:
	$a0
}