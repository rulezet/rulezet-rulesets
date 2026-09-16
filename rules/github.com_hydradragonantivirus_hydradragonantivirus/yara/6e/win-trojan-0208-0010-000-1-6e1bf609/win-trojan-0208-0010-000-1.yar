rule Win_Trojan__0208_0010_000_1
{
strings:
	$a0 = { b8013dba9e00cd2193b440b94f10ba0001cd21b43ecd21b44febcfb42acd2180fa0f7536909090 }


condition:
	$a0
}