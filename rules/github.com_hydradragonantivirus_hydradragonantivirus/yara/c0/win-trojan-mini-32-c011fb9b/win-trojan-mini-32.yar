rule Win_Trojan_Mini_32
{
strings:
	$a0 = { 2d03008986c500b440b9c8008bd5cd21b000e82600b440b903008d96c400cd215a5983c91fb80157 }


condition:
	$a0
}