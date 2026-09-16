rule Win_Trojan_VGEN_124
{
strings:
	$a0 = { 8b6efafb4d4d061efcb84344cd213d3e3a75311f078cc00510002e01864800cc2e03864a00fa8ed02e8ba64c0033 }


condition:
	$a0
}