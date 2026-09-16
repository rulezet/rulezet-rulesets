rule Win_Trojan_Agent_33935
{
strings:
	$a0 = { 60e800000000585083c40409c061eb5c }


condition:
	$a0
}