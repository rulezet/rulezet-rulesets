rule Win_Trojan_Kiss_1
{
strings:
	$a0 = { 02b90200b43fcd21813ea102f0f07428c706a102f0f0e829ffb440ba9702b90300cd217213e8 }


condition:
	$a0
}