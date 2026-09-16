rule Win_Trojan_SillyC_22
{
strings:
	$a0 = { 8905b440b1718d960301cd21e80e00b4404fe80100c3b1038bd7cd21c3b8023dba9e00cd21 }


condition:
	$a0
}