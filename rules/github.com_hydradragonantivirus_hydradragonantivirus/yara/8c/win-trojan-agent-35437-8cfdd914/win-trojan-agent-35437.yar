rule Win_Trojan_Agent_35437
{
strings:
	$a0 = { e803000000eb01e9bb55000000e803000000eb01e8e8 }

	$a1 = { 2b1b627c3868724f5641ec }


condition:
	$a0 and $a1
}