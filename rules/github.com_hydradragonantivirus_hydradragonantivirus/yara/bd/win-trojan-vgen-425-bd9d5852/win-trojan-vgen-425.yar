rule Win_Trojan_VGEN_425
{
strings:
	$a0 = { 01fc9c580d0020509d9c58a90020751d9090061f8cd80510002e01842d0005f0ff8ed0bcfeffeb00ea0000f0ff66 }


condition:
	$a0
}