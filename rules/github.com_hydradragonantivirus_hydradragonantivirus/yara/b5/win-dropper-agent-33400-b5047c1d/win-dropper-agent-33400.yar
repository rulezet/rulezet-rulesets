rule Win_Dropper_Agent_33400
{
strings:
	$a0 = { 8bd86a0068800000006a026a006a026800000040ff75f468687e40008d45ec8bd6e82cbaffffff75ec8d45f0ba03000000e800bbffff8b45f0e884bbffff50e81ec7ffff }


condition:
	$a0
}