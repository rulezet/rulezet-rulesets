rule Win_Trojan_Ale_1
{
strings:
	$a0 = { 5bb40980c437b977078d960b01cd21e80500e91ef9 }


condition:
	$a0
}