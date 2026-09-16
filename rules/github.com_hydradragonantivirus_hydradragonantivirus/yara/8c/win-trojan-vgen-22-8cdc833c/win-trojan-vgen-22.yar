rule Win_Trojan_VGEN_22
{
strings:
	$a0 = { 9c83ec04501e06fb2e833e1c00ff7424c7060600f0fe8bec8c5e08c7460600018cdd8cc8050d018bd8b9f00f03c18ec0 }


condition:
	$a0
}