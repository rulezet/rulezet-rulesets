rule Win_Trojan_Kitana_1
{
strings:
	$a0 = { 93ba8000cd13c747fe55aa96381fb30275eec30e1f87deff0e1304cd12b176d3c08ec033fff3 }


condition:
	$a0
}