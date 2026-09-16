rule Win_Trojan_DeadTie_1
{
strings:
	$a0 = { 060f849f0066817d1afffb00000f879300b440cd21b8004233c999cd21b440b90002b601cd21 }


condition:
	$a0
}