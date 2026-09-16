rule Win_Trojan_P1_4
{
strings:
	$a0 = { 47033d8bf733d2b87a02503355224747487df85931542246464979f8 }


condition:
	$a0
}