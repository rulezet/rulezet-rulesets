rule Win_Trojan_RTPDV_1
{
strings:
	$a0 = { fc002d03012ea34d015bb440e87300722a0e1f0e0732c0e86f00b440b90300ba4c01e85d007214 }


condition:
	$a0
}