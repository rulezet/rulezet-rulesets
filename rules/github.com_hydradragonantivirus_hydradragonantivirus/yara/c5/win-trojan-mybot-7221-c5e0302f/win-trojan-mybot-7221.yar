rule Win_Trojan_Mybot_7221
{
strings:
	$a0 = { 77dbcc109cfbf85d9dbede6233421e2312dc4873962e0a44a33fce580249e600aef86eb71196ec023279e06476e7497d5c474a90d7ab10bcdb90e4cff4c9d2010581effbfbdd94a8560d9981bb51 }


condition:
	$a0
}