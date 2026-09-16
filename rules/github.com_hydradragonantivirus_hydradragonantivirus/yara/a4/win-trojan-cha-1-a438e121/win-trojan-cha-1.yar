rule Win_Trojan_Cha_1
{
strings:
	$a0 = { b80242cd21720aba0000b9fd05b440cd21b80057cd2180c91fb80157cd21b43ecd21e84301 }


condition:
	$a0
}