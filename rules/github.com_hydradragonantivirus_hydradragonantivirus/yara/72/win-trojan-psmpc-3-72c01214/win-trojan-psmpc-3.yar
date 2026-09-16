rule Win_Trojan_PSMPC_3
{
strings:
	$a0 = { 2180fe06721280fa09720d81f9c9077207b42ccd2180fa50b41aba800081fc484b7403cd21 }


condition:
	$a0
}