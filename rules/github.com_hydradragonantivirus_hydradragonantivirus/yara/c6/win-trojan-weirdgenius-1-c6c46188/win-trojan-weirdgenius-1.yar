rule Win_Trojan_WeirdGenius_1
{
strings:
	$a0 = { 0807b440cd215ae8c5005bcfb45b8d966a04b90000cd21720c93b983008d964e07b440cd21c359 }


condition:
	$a0
}