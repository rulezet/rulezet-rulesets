rule Win_Trojan_Stalkerx_1
{
strings:
	$a0 = { 3002b44033d2b98a02cd218f0667008f066500c3b80200bb00a0cd318ec0b80200bb0000cd31 }


condition:
	$a0
}