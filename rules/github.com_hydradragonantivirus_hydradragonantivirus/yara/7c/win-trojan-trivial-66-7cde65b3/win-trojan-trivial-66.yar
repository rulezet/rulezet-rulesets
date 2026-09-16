rule Win_Trojan_Trivial_66
{
strings:
	$a0 = { ba9e00cd21722793b80057cd215152ba0001b440b98b0090cd215a59b80157cd21b43ecd21 }


condition:
	$a0
}