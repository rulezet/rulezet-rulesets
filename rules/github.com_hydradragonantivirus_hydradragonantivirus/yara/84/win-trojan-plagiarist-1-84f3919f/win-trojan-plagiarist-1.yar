rule Win_Trojan_Plagiarist_1
{
strings:
	$a0 = { c30004812f020089deadb106d3e08ec0b9030051b80402bb00008b0e427c8b16447ccd13 }


condition:
	$a0
}