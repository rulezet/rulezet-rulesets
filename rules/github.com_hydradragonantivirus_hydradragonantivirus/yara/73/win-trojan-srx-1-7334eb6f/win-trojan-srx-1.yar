rule Win_Trojan_SRX_1
{
strings:
	$a0 = { 19000e1f8d166c019cfa2eff1e08012e8b0ebf012e }


condition:
	$a0
}