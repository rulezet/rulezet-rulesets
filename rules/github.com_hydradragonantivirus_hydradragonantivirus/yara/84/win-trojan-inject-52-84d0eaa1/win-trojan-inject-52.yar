rule Win_Trojan_Inject_52
{
strings:
	$a0 = { 6801504000e801000000c3c389972f232c14193d1b97bb9a1b7ce2b924e225586e697e73d8373fccc5 }


condition:
	$a0
}