rule Win_Trojan_Creeper_10
{
strings:
	$a0 = { 709081f3d08f2e8087a8008543eb0075f5637b7b75d90651fe6591fe41ab818999899aae7ad2fe3f81074efe667e }


condition:
	$a0
}