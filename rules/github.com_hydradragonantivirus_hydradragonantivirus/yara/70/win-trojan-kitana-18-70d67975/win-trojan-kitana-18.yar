rule Win_Trojan_Kitana_18
{
strings:
	$a0 = { 740cb801034150cd135887dee2f8c30e1fff0ef4ffcd12b196d3c08ec033fff3a44141affd }


condition:
	$a0
}