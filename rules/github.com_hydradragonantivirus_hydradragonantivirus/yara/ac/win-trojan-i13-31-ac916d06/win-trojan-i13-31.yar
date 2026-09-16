rule Win_Trojan_I13_31
{
strings:
	$a0 = { ae2ff1414ad86914266dd852dd4f2acc7718f1334ad969272412d852dd1624ccb616f133dc137b6c }


condition:
	$a0
}