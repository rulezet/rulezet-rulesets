rule Win_Trojan_Etc_1
{
strings:
	$a0 = { 8b16020183c233cd2172cd89d68b043d }


condition:
	$a0
}