rule Win_Trojan_Shocker_staticsig_1
{
strings:
	$a0 = { 0f87a109cfa3e4be5ac240114fef69fe }


condition:
	$a0
}