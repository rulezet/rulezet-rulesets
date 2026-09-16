rule Win_Trojan_Small_4557
{
strings:
	$a0 = { 81c0bea040006845234500685232980068625446 }


condition:
	$a0
}