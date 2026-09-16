rule Win_Trojan_Quell_2
{
strings:
	$a0 = { e800005b81eb0d018bf3bf0001b90a00f3a4b4aacd213ca574e383c30a53b82135cd218bc35b538c }


condition:
	$a0
}