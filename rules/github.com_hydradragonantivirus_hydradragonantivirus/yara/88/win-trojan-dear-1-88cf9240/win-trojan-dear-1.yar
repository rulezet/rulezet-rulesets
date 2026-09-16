rule Win_Trojan_Dear_1
{
strings:
	$a0 = { 74061da2936887aebb4cd75aa21e5d77a9aedd5514d5759f61d2ee64d221f2e58acea97e5acd13 }


condition:
	$a0
}