rule Win_Trojan_Hide_1
{
strings:
	$a0 = { 4749463839[0-100]3c3f706870 }


condition:
	$a0
}