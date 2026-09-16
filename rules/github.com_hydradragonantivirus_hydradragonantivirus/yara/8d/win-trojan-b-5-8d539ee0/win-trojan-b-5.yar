rule Win_Trojan_B_5
{
strings:
	$a0 = { d8cd1248a31304b106d3e08ec0fcb9000133ffbe007cf3a5be4c00bf8300a5a54e4ec744fe }


condition:
	$a0
}