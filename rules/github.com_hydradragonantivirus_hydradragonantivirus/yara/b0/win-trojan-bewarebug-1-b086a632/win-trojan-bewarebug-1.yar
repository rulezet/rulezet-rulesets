rule Win_Trojan_BewareBug_1
{
strings:
	$a0 = { 060e1fe9a1d4014d5aa6001900010006003f03ffff14030002000000019a020500a8d44d002595a2ab00306a1ada01 }


condition:
	$a0
}