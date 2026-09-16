rule Win_Trojan_Yale_1
{
strings:
	$a0 = { 40008edba11300f7e32de0078ec00e }


condition:
	$a0
}