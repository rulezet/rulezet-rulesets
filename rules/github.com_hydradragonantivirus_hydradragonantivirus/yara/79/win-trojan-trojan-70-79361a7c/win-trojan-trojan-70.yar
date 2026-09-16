rule Win_Trojan_Trojan_70
{
strings:
	$a0 = { 0231944201d1c24e79f7 }


condition:
	$a0
}