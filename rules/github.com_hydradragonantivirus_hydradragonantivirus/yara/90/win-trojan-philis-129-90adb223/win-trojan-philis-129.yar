rule Win_Trojan_Philis_129
{
strings:
	$a0 = { 81c14249386d5481e94249386d }


condition:
	$a0
}