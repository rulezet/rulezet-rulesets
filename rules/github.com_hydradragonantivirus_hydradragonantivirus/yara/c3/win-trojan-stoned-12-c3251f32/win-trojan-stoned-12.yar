rule Win_Trojan_Stoned_12
{
strings:
	$a0 = { bc007cfbb404cd1a80f995774fe8c3ff1e07a14c002ea3b302a14e002ea3b502c7064c0009018c0e4e00b80102 }


condition:
	$a0
}