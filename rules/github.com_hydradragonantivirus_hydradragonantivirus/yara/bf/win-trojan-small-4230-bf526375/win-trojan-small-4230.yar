rule Win_Trojan_Small_4230
{
strings:
	$a0 = { 528bd7f7d287fa5a474ff7d7 }


condition:
	$a0
}