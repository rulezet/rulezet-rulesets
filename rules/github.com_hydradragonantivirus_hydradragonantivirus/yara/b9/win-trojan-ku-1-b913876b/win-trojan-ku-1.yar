rule Win_Trojan_Ku_1
{
strings:
	$a0 = { 8d7c020135478a25802501d0ec0064048bceb440cd21e81100b918008bd6b440cd2158 }


condition:
	$a0
}