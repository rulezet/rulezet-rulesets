rule Win_Trojan_VGEN_702
{
strings:
	$a0 = { 01e800005d83ed07b8ffffcd210ae4744f1e33c08ed8832e130402c51e84003e899eff013e8c9e01028cc34b8e }


condition:
	$a0
}