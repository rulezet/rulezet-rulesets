rule Win_Trojan_VGEN_540
{
strings:
	$a0 = { 4acd210e588ed88ec0b85346b90500bb0100cd2fb85346b90200bb0100cd2fb85346b90300bb }


condition:
	$a0
}