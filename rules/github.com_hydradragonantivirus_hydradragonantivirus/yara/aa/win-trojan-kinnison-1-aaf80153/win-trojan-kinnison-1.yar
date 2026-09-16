rule Win_Trojan_Kinnison_1
{
strings:
	$a0 = { 86c032c4e90000e800005f83ef038d750de8 }

	$a1 = { 8132????4d9075f8c3 }


condition:
	$a0 and $a1
}