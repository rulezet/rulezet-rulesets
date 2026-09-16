rule Win_Trojan_Kitana_6
{
strings:
	$a0 = { ba8000cd13c747fe55aa96381fb30275eec30e1f87deff0e1304cd12b178d3c08ec033fff3 }


condition:
	$a0
}