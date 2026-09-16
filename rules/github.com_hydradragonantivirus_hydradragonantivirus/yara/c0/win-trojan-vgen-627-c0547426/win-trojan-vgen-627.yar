rule Win_Trojan_VGEN_627
{
strings:
	$a0 = { 9d005589e581ec00069a02089d008dbe00fd16578dbe00fe16578dbe00ff165731c0509ab20a9d000ee829fabf }


condition:
	$a0
}