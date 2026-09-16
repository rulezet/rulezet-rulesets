rule Win_Trojan_Hackin_2
{
strings:
	$a0 = { 5b05cd21b8013dba9e00cd2193b440b9003cba0001cd21b44fb120ba5b05cd21b8013dba9e00cd }


condition:
	$a0
}