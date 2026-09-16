rule Win_Trojan_Peed_361
{
strings:
	$a0 = { 4783ff01741f81ff451400007f17b94b3f02ff4881c10fd0fd00ba01010010c1 }


condition:
	$a0
}