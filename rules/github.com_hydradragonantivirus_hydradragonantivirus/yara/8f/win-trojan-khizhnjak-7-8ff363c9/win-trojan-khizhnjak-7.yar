rule Win_Trojan_Khizhnjak_7
{
strings:
	$a0 = { 3db002cd211f7303e99000eb14901e2ea12c008ed8ba08 }


condition:
	$a0
}