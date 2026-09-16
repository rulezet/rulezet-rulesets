rule Win_Trojan_Vundo_32
{
strings:
	$a0 = { 60e892140000d2a3a0591effcc152a1b }


condition:
	$a0
}