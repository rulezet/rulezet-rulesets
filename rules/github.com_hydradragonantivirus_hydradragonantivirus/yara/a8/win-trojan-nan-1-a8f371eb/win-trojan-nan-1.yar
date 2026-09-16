rule Win_Trojan_Nan_1
{
strings:
	$a0 = { 5a595964891068dcc940008d45f8e8c467ffffc3e99e62ffffebf059595dc3ffffffff060000 }


condition:
	$a0
}