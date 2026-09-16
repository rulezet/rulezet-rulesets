rule Win_Trojan_Trivial_175
{
strings:
	$a0 = { 2a2e652ab44e89f2cd21b82e5bba9e00f2aeffafa0028f058bcecd2193b44073e5c3 }


condition:
	$a0
}