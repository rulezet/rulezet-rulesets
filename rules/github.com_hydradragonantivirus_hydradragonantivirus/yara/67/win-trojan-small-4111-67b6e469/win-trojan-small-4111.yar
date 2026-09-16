rule Win_Trojan_Small_4111
{
strings:
	$a0 = { 64a100000000bd0b????11e826000000cd }


condition:
	$a0
}