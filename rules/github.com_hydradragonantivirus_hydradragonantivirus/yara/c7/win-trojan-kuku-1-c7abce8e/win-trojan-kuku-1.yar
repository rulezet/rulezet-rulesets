rule Win_Trojan_Kuku_1
{
strings:
	$a0 = { 3c0a750cb42ccd2180e60775e3bd0100a11afa3dc501 }


condition:
	$a0
}