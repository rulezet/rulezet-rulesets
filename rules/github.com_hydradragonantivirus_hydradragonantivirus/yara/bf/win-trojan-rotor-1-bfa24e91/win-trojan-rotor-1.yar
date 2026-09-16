rule Win_Trojan_Rotor_1
{
strings:
	$a0 = { 5e83ee03eb01382e8a840900bb1c002e30004381fb2c0475f6 }


condition:
	$a0
}