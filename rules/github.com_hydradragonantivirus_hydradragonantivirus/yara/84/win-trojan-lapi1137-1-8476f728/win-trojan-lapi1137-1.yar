rule Win_Trojan_LAPI1137_1
{
strings:
	$a0 = { 024233c999cd21b440b912008d967e04cd21b440b95f048d961200cd21e894ff5a59b80157 }


condition:
	$a0
}