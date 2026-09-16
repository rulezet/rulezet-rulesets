rule Win_Trojan_Urod_2
{
strings:
	$a0 = { e800005e83ee04bf000187fe2bf7f7de8bdee8dc028cd91e060e1feb2790050053508b871f018bd858cd215bc3383c }


condition:
	$a0
}