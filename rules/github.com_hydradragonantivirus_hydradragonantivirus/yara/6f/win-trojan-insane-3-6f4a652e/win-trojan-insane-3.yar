rule Win_Trojan_Insane_3
{
strings:
	$a0 = { ee03012ec7845e03000190909090902e8c9c60038b8450032ea300018aa452032e88260201b8ffffcd213d4d4175 }


condition:
	$a0
}