rule Win_Trojan_DonaldDick_8
{
strings:
	$a0 = { 6f6c6570726f632e6578650000cc83f8010f84c104000083f81b0f846d04000083f81c }


condition:
	$a0
}