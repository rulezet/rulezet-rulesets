rule Win_Trojan_B_34
{
strings:
	$a0 = { b41acd218b2e2c01bae602b82425cd21b42acd2180fa0b740780fa177402eb0b }


condition:
	$a0
}