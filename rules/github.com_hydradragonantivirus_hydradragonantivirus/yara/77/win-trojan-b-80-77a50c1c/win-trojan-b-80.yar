rule Win_Trojan_B_80
{
strings:
	$a0 = { c075f5c6064c7d00cd1248a31304b106d3e08ec0fcb9000133ffbe007cf3a5be4c00bf9d00 }


condition:
	$a0
}