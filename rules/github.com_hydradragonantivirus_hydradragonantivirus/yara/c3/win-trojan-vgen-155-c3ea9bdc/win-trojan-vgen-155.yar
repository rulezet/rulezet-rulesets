rule Win_Trojan_VGEN_155
{
strings:
	$a0 = { ff8c0c812c217501f880ce2b56582eff8f787380f21d432f43515a80c278740414841c4881fbc3a175dff5e91f }


condition:
	$a0
}