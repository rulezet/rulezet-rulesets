rule Win_Trojan_Vobfus_32
{
strings:
	$a0 = { 72616d756e677520766964656574697065204c756e756c6972 }


condition:
	$a0
}