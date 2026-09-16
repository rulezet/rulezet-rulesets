rule Win_Trojan_Peed_59
{
strings:
	$a0 = { 680fccffff6852340200 }


condition:
	$a0
}