rule Win_Trojan_Grog_34
{
strings:
	$a0 = { 3dba89eacd2193ba60e6e8e900803e60e6e874bfbe63 }


condition:
	$a0
}