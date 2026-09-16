rule Win_Trojan_Monster_39
{
strings:
	$a0 = { 4aa2dc4bc1ce0548c3ce16488d4c4a4b876ac0ce1b48e8484bf26e6ff06d48499c876b1c }


condition:
	$a0
}