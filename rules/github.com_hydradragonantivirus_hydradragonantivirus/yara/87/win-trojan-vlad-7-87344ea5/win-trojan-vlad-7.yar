rule Win_Trojan_Vlad_7
{
strings:
	$a0 = { 09032e89a408032e8c940a032ec7841400cd20fa8cca8e }


condition:
	$a0
}