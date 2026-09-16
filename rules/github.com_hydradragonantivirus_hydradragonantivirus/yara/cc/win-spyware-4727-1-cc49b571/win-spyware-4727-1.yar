rule Win_Spyware_4727_1
{
strings:
	$a0 = { 5681f6674a00005e60eb01e8e800000000562bf35e87f787fe56d3ce5e5a }


condition:
	$a0
}