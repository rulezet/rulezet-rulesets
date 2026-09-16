rule Win_Trojan_HackTool_55
{
strings:
	$a0 = { 48494748204f5242495420494f4e2043414e4e4f4e205354414e44494e47204259 }

	$a1 = { 686f6963 }


condition:
	$a0 and $a1
}