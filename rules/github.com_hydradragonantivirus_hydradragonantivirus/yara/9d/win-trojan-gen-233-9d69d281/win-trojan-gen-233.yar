rule Win_Trojan_Gen_233
{
strings:
	$a0 = { 05915080ffbdede8c70c8be5a3fb2c3018b86650b808ecfcb30f3becb88001ef0480effc7509fe }


condition:
	$a0
}