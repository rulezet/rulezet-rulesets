rule Win_Trojan_Small_4256
{
strings:
	$a0 = { 60e8??000000[0-220]43333333 }


condition:
	$a0
}