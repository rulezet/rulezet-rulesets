rule Win_Trojan_Joker_3
{
strings:
	$a0 = { 450721071d49276d20736f206d75 }


condition:
	$a0
}