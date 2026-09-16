rule Win_Trojan_VHP_4
{
strings:
	$a0 = { b440b908038bd681ea2a02cd21721d }


condition:
	$a0
}