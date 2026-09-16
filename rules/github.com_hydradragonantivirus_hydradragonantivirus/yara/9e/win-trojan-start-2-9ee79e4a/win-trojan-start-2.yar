rule Win_Trojan_Start_2
{
strings:
	$a0 = { c9cdcdcdcdcdcdcdcd2024746172742e3232303020566972757320cdcdcdcdcdcdcdcdbb00ba }


condition:
	$a0
}