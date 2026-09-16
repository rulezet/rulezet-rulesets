rule Win_Trojan_VHP_3
{
strings:
	$a0 = { b9f5028bd681ea2c02cd21721d3d }


condition:
	$a0
}