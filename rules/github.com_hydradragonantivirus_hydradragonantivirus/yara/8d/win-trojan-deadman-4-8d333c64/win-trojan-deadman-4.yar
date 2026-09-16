rule Win_Trojan_Deadman_4
{
strings:
	$a0 = { 99cd2133c8750fb8004299cd21b440b11cba6b02cd215a59b80157cd21b43ecd21b8014333 }


condition:
	$a0
}