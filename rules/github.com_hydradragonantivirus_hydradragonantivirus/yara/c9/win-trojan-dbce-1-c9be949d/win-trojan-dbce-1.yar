rule Win_Trojan_DBCE_1
{
strings:
	$a0 = { 0df3a4be8d0eb9300d802c0746e2fab440b94b0dba780ecd21b801578b0e610d8b165f0dcd21 }


condition:
	$a0
}