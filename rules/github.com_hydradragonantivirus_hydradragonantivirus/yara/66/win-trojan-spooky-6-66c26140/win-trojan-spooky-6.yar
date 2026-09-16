rule Win_Trojan_Spooky_6
{
strings:
	$a0 = { 1e0e0e1f07e800005d81ed0901b42fcd2106530e07b41a8d968802cd218dbe39028db64102b90400f3a5b44e8d9649 }


condition:
	$a0
}