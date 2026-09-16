rule Win_Adware_Webhancer_10
{
strings:
	$a0 = { 6dd12a77656248616e63657200000077656268646c6c2e646c6c005c }


condition:
	$a0
}