rule Win_Trojan_Zlob_2220
{
strings:
	$a0 = { 687c0a00006860314000e8e109000033db889d84feffff889d80fdffff889d82fdffff889d7c }


condition:
	$a0
}