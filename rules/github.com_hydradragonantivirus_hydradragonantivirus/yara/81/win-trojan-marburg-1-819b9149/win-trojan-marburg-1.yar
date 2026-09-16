rule Win_Trojan_Marburg_1
{
strings:
	$a0 = { 1d03b9b101fcf2a4b80103b90200bb1d03cd13722cb8010249cd137224b80103b90300cd132e88 }


condition:
	$a0
}