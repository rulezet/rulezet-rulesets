rule Win_Trojan_Small_4534
{
strings:
	$a0 = { 8da80d74400068533445006a006a00ff157c7c4000 }


condition:
	$a0
}