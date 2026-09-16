rule Win_Trojan_Small_4077
{
strings:
	$a0 = { 6a0068590100006a00e816000000 }


condition:
	$a0
}