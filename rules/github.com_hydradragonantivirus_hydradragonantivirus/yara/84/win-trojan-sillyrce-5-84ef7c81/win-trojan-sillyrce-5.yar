rule Win_Trojan_SillyRCE_5
{
strings:
	$a0 = { e800005b0e1f80bfa2010074118cc00387ab0105100050ffb7a901eb0c90c487ad01a300018c060201068bcbb82135cd }


condition:
	$a0
}