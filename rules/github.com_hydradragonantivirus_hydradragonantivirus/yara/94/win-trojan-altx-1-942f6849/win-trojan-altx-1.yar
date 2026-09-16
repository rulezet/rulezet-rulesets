rule Win_Trojan_Altx_1
{
strings:
	$a0 = { 032e8c0614008cc88ed88ec0e80e00eb1d9037080100000086c4cd21c3be30008bfeb91f05ad90351503abe2f8c3 }


condition:
	$a0
}