rule Win_Trojan_Timehalf_1
{
strings:
	$a0 = { 9a0000f5005589e5bf860a0e57bfae331e5768ff009a880bf500c606520054c606ff0100c60600021ee88efbe8fef9b0 }


condition:
	$a0
}