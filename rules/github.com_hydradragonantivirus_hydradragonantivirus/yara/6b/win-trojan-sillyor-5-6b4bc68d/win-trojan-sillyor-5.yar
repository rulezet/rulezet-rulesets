rule Win_Trojan_SillyOR_5
{
strings:
	$a0 = { 8ec00e1f33ffb144f3a48ed8ba3f00b8ff25cd21ba1e00b021cdffc380fc3e751c1e52515033c933d2b80042cdff }


condition:
	$a0
}