rule Win_Trojan_Io_2
{
strings:
	$a0 = { 3c3f70687020696e636c7564652822696f2e70687022293b203f3e }


condition:
	$a0
}