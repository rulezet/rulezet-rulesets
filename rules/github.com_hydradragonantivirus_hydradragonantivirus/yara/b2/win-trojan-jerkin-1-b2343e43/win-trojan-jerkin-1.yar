rule Win_Trojan_Jerkin_1
{
strings:
	$a0 = { cce8000058cc505983c100cc33db8be981ed060033c95359eb00b41a8d968f00cd21e82600e83100cd202a2e636f }


condition:
	$a0
}