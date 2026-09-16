rule Win_Trojan__0461_0006_000_1
{
strings:
	$a0 = { 023dba9e00cd2193b440b9b400ba0001cd21b43ecd21b44febdcb409ba3501cd21cd202a2e63 }


condition:
	$a0
}