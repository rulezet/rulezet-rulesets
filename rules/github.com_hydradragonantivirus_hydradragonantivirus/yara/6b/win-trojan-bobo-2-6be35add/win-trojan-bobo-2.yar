rule Win_Trojan_Bobo_2
{
strings:
	$a0 = { 5db92f0581ed0b0090bf24008abe070003fd303d83c701e2f9be01008af4a5a5a5b9aa4acc203cb1b174160f1e }


condition:
	$a0
}