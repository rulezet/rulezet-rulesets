rule Win_Trojan_Inject_58
{
strings:
	$a0 = { 72414b5465787414416c692d3b50dc676e8ade2a430d6bf7e2ceb645bae40fe46961a95f83df14940f }


condition:
	$a0
}