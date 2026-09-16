rule Win_Trojan_CONFIG_1
{
strings:
	$a0 = { 0103600ee8d3fefcb9c001be00018d7f3ef3a4c707eb3e61cd13eb37009c60b800121e0699cd2f }


condition:
	$a0
}