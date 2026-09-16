rule Win_Dropper_Agent_35451
{
strings:
	$a0 = { 558bec83c4f05356837d0c010f852301000033dbff }

	$a1 = { 333630747261792e657865 }

	$a2 = { 687474703a2f2f }

	$a3 = { 5c6d736966666569 }


condition:
	$a0 and $a1 and $a2 and $a3
}