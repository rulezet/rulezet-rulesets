rule Win_Trojan_ACG_1
{
strings:
	$a0 = { 944b1ac1ba710e85dd81e20670b03dcd21e965028aed1180fc3a7403e9080d3e668b1de901 }


condition:
	$a0
}