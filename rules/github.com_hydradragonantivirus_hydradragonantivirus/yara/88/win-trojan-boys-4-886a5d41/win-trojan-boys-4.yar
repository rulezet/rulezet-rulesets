rule Win_Trojan_Boys_4
{
strings:
	$a0 = { cd217303e9bd005e5683c625ad3d00fd }


condition:
	$a0
}