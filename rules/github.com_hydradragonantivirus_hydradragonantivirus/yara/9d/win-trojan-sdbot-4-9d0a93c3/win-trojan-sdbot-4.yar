rule Win_Trojan_Sdbot_4
{
strings:
	$a0 = { 6c6cb60bc4dc0ff9076a27b2377b2e406928f3fb84672e6c7a27601b1e000028450724000000ff }


condition:
	$a0
}