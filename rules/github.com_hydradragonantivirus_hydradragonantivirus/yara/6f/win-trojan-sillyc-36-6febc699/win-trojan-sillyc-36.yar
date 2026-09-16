rule Win_Trojan_SillyC_36
{
strings:
	$a0 = { 0389450ab440ba80ff01fab18acd21b8004231c931d2cd }


condition:
	$a0
}