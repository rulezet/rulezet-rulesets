rule Win_Trojan_Nucleii_3
{
strings:
	$a0 = { ffeb05b8004ccd21e2f7e800005d81ed1201e9d4058db652018bfee80200eb2dacd0c8d0c8d0c8d0c83e32865101f6d0f6d83e32865101f6d8f6d03e32865101d0c8d0c8d0c8d0c8aae2d5c3 }


condition:
	$a0
}