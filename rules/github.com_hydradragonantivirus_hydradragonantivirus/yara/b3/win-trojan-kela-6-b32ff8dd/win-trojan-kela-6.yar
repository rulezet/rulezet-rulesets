rule Win_Trojan_Kela_6
{
strings:
	$a0 = { ed09c3b440b90000e8caffc3ba0001b9e209b440e8beffc3b440b91800baef09e8b2ffc3b4 }


condition:
	$a0
}