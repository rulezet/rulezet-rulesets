rule Win_Trojan_MackBanner_1
{
strings:
	$a0 = { 7bcc775965d4716b5bd3ce216d3d41d6e4d99fdadf99d3f669619bdeaafca1d866dc64e0a4e767e1 }


condition:
	$a0
}