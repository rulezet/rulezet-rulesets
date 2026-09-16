rule Win_Trojan_SillyOR_4
{
strings:
	$a0 = { 8ec033ffb142f3a48ed8ba3d00b8ff25cd21ba1c00b021cdffc380fc3e751c1e52515033c933d2b80042cdffb142 }


condition:
	$a0
}