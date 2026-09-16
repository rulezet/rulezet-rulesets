rule Win_Trojan_Delf_1517
{
strings:
	$a0 = { 5568e940410064ff306489206a0068f8404100e8521effff }


condition:
	$a0
}