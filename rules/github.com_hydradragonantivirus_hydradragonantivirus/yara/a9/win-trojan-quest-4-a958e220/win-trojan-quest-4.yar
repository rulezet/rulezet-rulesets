rule Win_Trojan_Quest_4
{
strings:
	$a0 = { b8023dcc72??930e1fb9????b43f99cc72??813e00001ee974??813e00004d5a74??b8024233c999cc }


condition:
	$a0
}