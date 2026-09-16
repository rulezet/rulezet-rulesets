rule Win_Trojan_SillyC_3
{
strings:
	$a0 = { 51b928015133c933d2b80242cd215951b440ba00fdcd2133c933d2b80042cd21595ab440cd }


condition:
	$a0
}