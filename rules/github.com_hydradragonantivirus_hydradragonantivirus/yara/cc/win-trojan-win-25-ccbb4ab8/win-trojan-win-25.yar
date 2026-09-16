rule Win_Trojan_Win_25
{
strings:
	$a0 = { 043c007502ebfe8bfe8ac883c70280e901723e8ad180ca80885503b408515756cd135e5f890d8b }


condition:
	$a0
}