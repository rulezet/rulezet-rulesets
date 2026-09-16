rule Win_Trojan_Birgit_6
{
strings:
	$a0 = { b9e7038d960a01cd215b53b801573e8b8e04033e8b960603cd215bb43ecd2168014358ba9e00 }


condition:
	$a0
}