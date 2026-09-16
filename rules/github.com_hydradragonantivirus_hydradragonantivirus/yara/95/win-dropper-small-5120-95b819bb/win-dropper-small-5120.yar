rule Win_Dropper_Small_5120
{
strings:
	$a0 = { f3a483c9ffbfa8104000f2ae }


condition:
	$a0
}