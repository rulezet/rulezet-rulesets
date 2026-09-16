rule Win_Trojan_PPZ_1
{
strings:
	$a0 = { 81ee03012e8c9cd60f0bf674298db40001bfb5121e0e1ffecfb104d3eb8cc803d883c30a8ec3b9b51103f1fdf3 }


condition:
	$a0
}