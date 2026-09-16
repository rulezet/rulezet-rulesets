rule Win_Trojan_Killroy_1
{
strings:
	$a0 = { fa33c08ec08ed88ed0bc007cfbb80102bb????b90100ba0100cd13b80102cd13721dbe007cbf????b90b00fcf3a483c61383c713b9e001f3a441b80103cd13 }


condition:
	$a0
}