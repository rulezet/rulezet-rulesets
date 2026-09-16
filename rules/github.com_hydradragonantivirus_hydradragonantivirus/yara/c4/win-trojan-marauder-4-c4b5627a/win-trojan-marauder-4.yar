rule Win_Trojan_Marauder_4
{
strings:
	$a0 = { 5d81c646018bfefcad33861901ab49e302ebf5555e5a }


condition:
	$a0
}