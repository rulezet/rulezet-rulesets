rule Win_Spyware_4222_1
{
strings:
	$a0 = { 53435b60f7d3f7d3e800000000520f02 }


condition:
	$a0
}