rule Win_Spyware_59727_1
{
strings:
	$a0 = { 558becb9100000006a006a004975f9 }

	$a1 = { 656c656d656e74636c69656e742e657865 }

	$a2 = { 5c756e74446f776f726b }


condition:
	$a0 and $a1 and $a2
}