rule Win_Trojan_Kode4_8
{
strings:
	$a0 = { 3de9750d8b4d012d8f013bc17503eb639033c933d2b800 }


condition:
	$a0
}