rule Win_Trojan_V_95
{
strings:
	$a0 = { 02890e9000a39200a104002d870474142b064c003d3b }


condition:
	$a0
}