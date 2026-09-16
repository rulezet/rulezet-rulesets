rule Win_Trojan_SillyRC_29
{
strings:
	$a0 = { 83ee0356b84b4bcd21734e9090b44abbffffcd2183eb2290b44acd21b448bb1c00cd217234909050b82135cd21899c }


condition:
	$a0
}