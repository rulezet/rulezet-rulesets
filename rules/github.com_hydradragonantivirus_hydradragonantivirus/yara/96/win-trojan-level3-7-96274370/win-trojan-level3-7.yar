rule Win_Trojan_Level3_7
{
strings:
	$a0 = { 0800c35e43b94cff1e235857f898c2462209e936dddc937e7261fbf5ef }


condition:
	$a0
}