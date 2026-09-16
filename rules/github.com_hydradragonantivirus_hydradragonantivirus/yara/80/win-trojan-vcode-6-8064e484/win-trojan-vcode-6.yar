rule Win_Trojan_VCode_6
{
strings:
	$a0 = { 1c00ba3400b440cd21721139c875238b160c008b0e0e00b80042cd217214e813fa8b1e0000 }


condition:
	$a0
}