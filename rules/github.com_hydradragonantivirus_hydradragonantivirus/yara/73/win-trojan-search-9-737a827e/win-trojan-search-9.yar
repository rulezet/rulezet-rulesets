rule Win_Trojan_Search_9
{
strings:
	$a0 = { 894604b440b935018bd5cd2190c64600e98f4601b8 }


condition:
	$a0
}