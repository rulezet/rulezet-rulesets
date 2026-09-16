rule Win_Dropper_Small_3522
{
strings:
	$a0 = { bd3b104000e875ffffffbf00104000ff554883c707ff554883c708ff5548bb00144000 }


condition:
	$a0
}