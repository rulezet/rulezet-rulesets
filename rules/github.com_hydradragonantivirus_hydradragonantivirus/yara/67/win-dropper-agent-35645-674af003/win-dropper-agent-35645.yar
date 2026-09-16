rule Win_Dropper_Agent_35645
{
strings:
	$a0 = { be20104000b9730000008b068b56 }

	$a1 = { 57494e494e49542e494e490052656e616d65 }

	$a2 = { 20416e7469766972757320 }


condition:
	$a0 and $a1 and $a2
}