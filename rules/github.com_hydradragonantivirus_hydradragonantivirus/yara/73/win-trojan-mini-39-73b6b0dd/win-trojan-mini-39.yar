rule Win_Trojan_Mini_39
{
strings:
	$a0 = { 03008986ea00b440b9ed008bd5cd21b000e81b00b440b903008d96e900cd215a5983c91fb80157 }


condition:
	$a0
}