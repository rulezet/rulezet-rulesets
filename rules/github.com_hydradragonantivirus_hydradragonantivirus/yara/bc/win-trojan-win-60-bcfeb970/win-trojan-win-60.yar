rule Win_Trojan_Win_60
{
strings:
	$a0 = { 633a5c72656770617463682e726567[0-140]5c424153534d4f442e646c6c }


condition:
	$a0
}