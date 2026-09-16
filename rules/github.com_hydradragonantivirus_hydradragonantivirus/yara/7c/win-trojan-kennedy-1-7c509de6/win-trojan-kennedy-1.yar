rule Win_Trojan_Kennedy_1
{
strings:
	$a0 = { 8bfab90300cd21803de97405e87e00 }


condition:
	$a0
}