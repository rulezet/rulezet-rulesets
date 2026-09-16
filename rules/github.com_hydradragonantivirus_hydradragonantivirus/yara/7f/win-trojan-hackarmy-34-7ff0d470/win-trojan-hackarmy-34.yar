rule Win_Trojan_Hackarmy_34
{
strings:
	$a0 = { 2fc2feee702e680661726d792e746b4f3935cbffffcb30302323632323006772616e6461640057696e736f207dfbffff }


condition:
	$a0
}