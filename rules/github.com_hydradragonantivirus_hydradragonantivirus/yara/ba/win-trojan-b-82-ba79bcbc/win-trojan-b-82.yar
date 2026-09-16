rule Win_Trojan_B_82
{
strings:
	$a0 = { 8ed8bb13048b0748488907b106d3e08ec01e0e1f33ffbe007cb90001f3a51fb9050051b80102 }


condition:
	$a0
}