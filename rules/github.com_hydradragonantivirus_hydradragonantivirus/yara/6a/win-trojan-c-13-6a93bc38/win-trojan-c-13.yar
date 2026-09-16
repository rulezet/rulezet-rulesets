rule Win_Trojan_C_13
{
strings:
	$a0 = { 0300000001e800005d81ed09018db6230189f7b901028a260501feccac32c4aae2fa }


condition:
	$a0
}