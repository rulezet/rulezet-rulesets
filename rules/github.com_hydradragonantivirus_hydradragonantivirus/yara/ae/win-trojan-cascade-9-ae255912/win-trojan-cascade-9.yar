rule Win_Trojan_Cascade_9
{
strings:
	$a0 = { 87220101740f8dbf4501bc5a06313d3125474c75f8 }


condition:
	$a0
}