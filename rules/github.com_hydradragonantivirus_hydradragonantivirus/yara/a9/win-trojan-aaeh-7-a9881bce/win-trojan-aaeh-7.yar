rule Win_Trojan_AAEH_7
{
strings:
	$a0 = { 2d433030302d6c6b6b746b }

	$a1 = { 526c68fff510000000aa5e1b000400fd69e0fef5030000006c20ff5228d0fe0000f5040000006c20ff520420ff6c7cfe }


condition:
	$a0 and $a1
}