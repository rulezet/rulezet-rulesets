rule Win_Spyware_ye_151
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]945a9e6bafd6812b557a25973f641c }


condition:
	$a0
}