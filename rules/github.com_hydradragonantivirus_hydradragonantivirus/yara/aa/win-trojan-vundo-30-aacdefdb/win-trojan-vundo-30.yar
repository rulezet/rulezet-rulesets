rule Win_Trojan_Vundo_30
{
strings:
	$a0 = { 60e8da0b0000e801a6e7943d328300397e4392 }


condition:
	$a0
}