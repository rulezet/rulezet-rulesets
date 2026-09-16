rule Win_Trojan_Pest_2
{
strings:
	$a0 = { 8db6580a2e8b04f54b484afec032c441f943fd484887ef2e31460087fd43f942f9fd02e043fcfb48f5438afc8bef2e307e0033ed4a49fb4243fafa47fafc414b9090408bd78d9e560a3bd376c0 }


condition:
	$a0
}