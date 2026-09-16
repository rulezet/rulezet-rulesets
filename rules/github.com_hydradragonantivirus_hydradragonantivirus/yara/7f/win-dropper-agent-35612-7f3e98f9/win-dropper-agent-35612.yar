rule Win_Dropper_Agent_35612
{
strings:
	$a0 = { 5053575283cf0d56510f85b7ffffffb843986d625b56 }

	$a1 = { 541b773d7757 }

	$a2 = { 6937294a387a501bb3c9df }


condition:
	$a0 and $a1 and $a2
}