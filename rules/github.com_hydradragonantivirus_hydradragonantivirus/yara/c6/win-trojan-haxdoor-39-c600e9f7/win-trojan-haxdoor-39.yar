rule Win_Trojan_Haxdoor_39
{
strings:
	$a0 = { 70733a2f2f3c6d42217e652d676f6c64002f2c2f00befb3bfb79776964a332311768 }


condition:
	$a0
}