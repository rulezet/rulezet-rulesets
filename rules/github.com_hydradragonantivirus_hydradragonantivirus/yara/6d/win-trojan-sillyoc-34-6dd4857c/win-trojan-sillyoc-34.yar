rule Win_Trojan_SillyOC_34
{
strings:
	$a0 = { 57cd215152ba9e00b8013dcd2193b440b98802ba0001cd21b43ecd215a59b80157cd21b44fcd }


condition:
	$a0
}