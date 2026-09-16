rule Win_Trojan__0366_0006_000_1
{
strings:
	$a0 = { 40cd2172341e8cc08ed8b9c40233d2b440cd211f722333c933d2b80042cd21b920008d96db03b4 }


condition:
	$a0
}