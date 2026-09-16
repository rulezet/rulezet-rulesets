rule Win_Trojan_Lauren_5
{
strings:
	$a0 = { 028dbe17018035009c0ee81300e2f6c3e8ebff5a59582ecd2190e8e1ffe966fe47b003cf5c }


condition:
	$a0
}