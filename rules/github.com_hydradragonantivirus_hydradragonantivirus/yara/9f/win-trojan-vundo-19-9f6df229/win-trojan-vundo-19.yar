rule Win_Trojan_Vundo_19
{
strings:
	$a0 = { 60e8da1e0000e0995eeb01 }


condition:
	$a0
}