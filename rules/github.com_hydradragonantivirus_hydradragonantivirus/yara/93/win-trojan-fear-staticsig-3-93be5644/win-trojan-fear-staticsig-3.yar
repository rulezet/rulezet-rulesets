rule Win_Trojan_Fear_staticsig_3
{
strings:
	$a0 = { 5eb6a0b3dba4840e6147909fc7bbf85ec0193fbc239d481c85865c8d5dc438c246 }


condition:
	$a0
}