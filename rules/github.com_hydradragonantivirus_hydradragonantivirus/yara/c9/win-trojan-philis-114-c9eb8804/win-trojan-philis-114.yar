rule Win_Trojan_Philis_114
{
strings:
	$a0 = { 56e806000000e8eb09e9e9e85e46ffe6e9e85e6081f70c4b000081f70c4b0000e8000000000f00e35ab8dc000000 }


condition:
	$a0
}