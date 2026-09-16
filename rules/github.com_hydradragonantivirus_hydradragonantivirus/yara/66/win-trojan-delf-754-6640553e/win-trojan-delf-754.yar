rule Win_Trojan_Delf_754
{
strings:
	$a0 = { 683f000f006a006a00e886feffff8bf068ff010f00685c37400056e87cfeffff8bf885ff7518 }


condition:
	$a0
}