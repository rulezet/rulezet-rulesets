rule Win_Trojan__0271_0006_000_1
{
strings:
	$a0 = { 40ba0001b90c00cd21b440ba9d01b99100cd21b43ecd21b44feb86b409ba9601cd21c32a2e4558 }


condition:
	$a0
}