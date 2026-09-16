rule Win_Trojan_Stack_1
{
strings:
	$a0 = { b452cd213d34127502cd208cc0a3f701 }


condition:
	$a0
}