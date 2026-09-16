rule Win_Trojan_RedSpider_1
{
strings:
	$a0 = { d1e8d1e8d1e8d1e88cda03c20510005033c050cb1e5351e80a032eff063b03b8badccd213d }


condition:
	$a0
}