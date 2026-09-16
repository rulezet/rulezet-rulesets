rule Win_Trojan_SillyOR_3
{
strings:
	$a0 = { c033ffb13cf3a48ed8ba1600b82125cd8ecd2080fc3e751c1e52515033c933d2b80042cd8eb13c0e1fb440cd8e }


condition:
	$a0
}