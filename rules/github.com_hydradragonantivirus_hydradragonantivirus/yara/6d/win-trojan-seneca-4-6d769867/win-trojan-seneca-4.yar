rule Win_Trojan_Seneca_4
{
strings:
	$a0 = { 21b9ff00ba0000cd267200b42ccd2180fe0a7706bbb902e8d2ffcd20bb }


condition:
	$a0
}