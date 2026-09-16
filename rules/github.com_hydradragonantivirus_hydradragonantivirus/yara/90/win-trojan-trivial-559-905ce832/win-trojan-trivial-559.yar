rule Win_Trojan_Trivial_559
{
strings:
	$a0 = { ba4a01b44ecd2172??ba9e00b8013dcd218bd8b440b9????ba0001cd2172 }


condition:
	$a0
}