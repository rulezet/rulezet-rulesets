rule Win_Trojan_Coffeshop_1
{
strings:
	$a0 = { 2135cd21891ef8008c06fa00ba0102b82125cd21b42acd213c05750db42ccd210af675055850e8 }


condition:
	$a0
}