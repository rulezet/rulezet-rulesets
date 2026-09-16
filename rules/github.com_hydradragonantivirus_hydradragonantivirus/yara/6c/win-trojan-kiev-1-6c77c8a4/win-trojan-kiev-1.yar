rule Win_Trojan_Kiev_1
{
strings:
	$a0 = { 72005589e581ec02029a230972008846ffb0013a46ff774fa2ae02eb04fe06ae028dbefffe1657bf68011e579a }


condition:
	$a0
}