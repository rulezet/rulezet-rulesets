rule Win_Trojan_Banker_6380
{
strings:
	$a0 = { 436f6e74656e742d446973706f736974696f6e3a20666f726d2d64617461 }

	$a1 = { 66696c74657270616b2e636f6d2f????2e7068 }


condition:
	$a0 and $a1
}