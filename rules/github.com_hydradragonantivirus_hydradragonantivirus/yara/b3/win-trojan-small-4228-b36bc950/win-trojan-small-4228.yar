rule Win_Trojan_Small_4228
{
strings:
	$a0 = { 50891424565e5151 }


condition:
	$a0
}