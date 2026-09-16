rule Win_Trojan_QQShou_13
{
strings:
	$a0 = { b962663cdb7022cabc48dbf102e1d1533cd143af21c334c06b1b6966978f9d8c2b67181321e94198924dcfa850d1a7fc59d2d90f0374cc4689aac3c4dff5 }


condition:
	$a0
}