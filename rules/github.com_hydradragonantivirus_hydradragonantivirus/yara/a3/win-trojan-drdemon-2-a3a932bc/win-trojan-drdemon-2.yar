rule Win_Trojan_DrDemon_2
{
strings:
	$a0 = { b1292e8a17d2c280f281d2ca80f2292e88174359e2e9 }


condition:
	$a0
}