rule Win_Trojan_Subliminal_2
{
strings:
	$a0 = { 3805e0f98bd783c203061f2ec706 }


condition:
	$a0
}