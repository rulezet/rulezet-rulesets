rule Win_Trojan_Vundo_23
{
strings:
	$a0 = { 60e8881c00007edf2cf58afb18715663 }


condition:
	$a0
}