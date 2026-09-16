rule Win_Trojan_Banker_6356
{
strings:
	$a0 = { 558bec83c4f0b8d8a54800e8d8b4f7ffa178d348008b00e808d3fcff8b0d54d5 }


condition:
	$a0
}