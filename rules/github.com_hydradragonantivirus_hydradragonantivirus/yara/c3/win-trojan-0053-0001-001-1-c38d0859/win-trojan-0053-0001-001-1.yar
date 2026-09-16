rule Win_Trojan__0053_0001_001_1
{
strings:
	$a0 = { 5880fc0074148acc32edb4401e061fcd211f7306e86e00eb24900e1fb8004233c933d2cd21 }


condition:
	$a0
}