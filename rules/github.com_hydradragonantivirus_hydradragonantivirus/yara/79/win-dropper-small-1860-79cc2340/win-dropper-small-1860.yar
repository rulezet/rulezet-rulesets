rule Win_Dropper_Small_1860
{
strings:
	$a0 = { 8d453868d06d410050e84235000059598d453850ff154c504100 }


condition:
	$a0
}