rule Win_Trojan_TimeReset_1
{
strings:
	$a0 = { 406563686f206f66660d0a74696d652030303a30303a30302c3030 }


condition:
	$a0
}