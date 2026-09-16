rule Win_Trojan_VGEN_85
{
strings:
	$a0 = { e901e800005d83ed07b8ffffcd210ae4744f1e33c08ed8832e130402c51e84002e899e00022e8c9e02028cc34b8e }


condition:
	$a0
}