rule Win_Trojan_SillyC_65
{
strings:
	$a0 = { a101892ea301b44eb92000ba9b01cd217266813e9a00a5007225813e9a0018f6771db8023dba9e00cd21721393b4 }


condition:
	$a0
}