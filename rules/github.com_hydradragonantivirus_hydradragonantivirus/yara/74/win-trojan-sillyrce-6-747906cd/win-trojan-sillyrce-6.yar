rule Win_Trojan_SillyRCE_6
{
strings:
	$a0 = { 5b0e1f80bfa2010074118cc00510000387ab0150ffb7a901eb0c90c487ad01a300018c060201068bcbb82135cd }


condition:
	$a0
}