rule Win_Trojan_Banker_6333
{
strings:
	$a0 = { 558becb8d0cb7236bba603c86250e800000000582da81a0000b96d }

	$a1 = { b83b6869964b5844805a56327c5f51277153 }


condition:
	$a0 and $a1
}