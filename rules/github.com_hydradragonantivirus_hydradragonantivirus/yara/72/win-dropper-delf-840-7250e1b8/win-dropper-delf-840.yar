rule Win_Dropper_Delf_840
{
strings:
	$a0 = { 55683d3c001164ff306489206a0068800000006a036a006a0168000000808d55f033c0e8cbeaffff8b45f0e87bf6ffff50e849fbffff }


condition:
	$a0
}