rule Win_Trojan_KillAV_40
{
strings:
	$a0 = { eb1066623a432b2b484f4f4b90e998e040 }

	$a1 = { 6e6f6433326b75692e657865[0-1]64727765627363642e }


condition:
	$a0 and $a1
}