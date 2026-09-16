rule Win_Trojan_Startpage_120
{
strings:
	$a0 = { fce8665fffff33c05a5959648910685cca40008d45ecba04000000e85c68ffffc3e9ca62ffffebeb8be55dc3ffffffff25000000687474703a2f2f7777772e637261636b706f72 }


condition:
	$a0
}