rule Win_Trojan_Wazzu_4
{
strings:
	$a0 = { 010100558e00000000010009030000c2010000020000000903 }


condition:
	$a0
}