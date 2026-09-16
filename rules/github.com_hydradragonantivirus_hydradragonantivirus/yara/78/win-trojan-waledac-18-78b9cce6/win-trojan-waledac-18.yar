rule Win_Trojan_Waledac_18
{
strings:
	$a0 = { 558bec83ec548b3de8ca49008d05eb204a0003f881ef }


condition:
	$a0
}