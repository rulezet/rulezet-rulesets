rule Win_Trojan_Subsys_13
{
strings:
	$a0 = { 9eb49557b05dd8482b2fd3e0f06c6fd9533fbc6994a4962ba3025ad1e482ae65374ead9a4c7d3b9c030809fc0ab503c6 }


condition:
	$a0
}