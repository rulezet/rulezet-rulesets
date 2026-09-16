rule Win_Trojan_VHP_5
{
strings:
	$a0 = { b440b908038bd681ea2a02cd21721d3d }


condition:
	$a0
}