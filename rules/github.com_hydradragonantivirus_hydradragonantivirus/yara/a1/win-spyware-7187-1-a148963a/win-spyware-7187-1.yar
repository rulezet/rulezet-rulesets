rule Win_Spyware_7187_1
{
strings:
	$a0 = { 565683c4048904245303db5b33c3eb008b042483 }


condition:
	$a0
}