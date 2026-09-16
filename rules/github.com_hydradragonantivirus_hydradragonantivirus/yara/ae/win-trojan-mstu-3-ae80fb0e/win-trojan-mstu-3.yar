rule Win_Trojan_MSTU_3
{
strings:
	$a0 = { 03c381ee0e018ec01e0e8ed8b41a }


condition:
	$a0
}