rule Win_Trojan_DOS_209
{
strings:
	$a0 = { be0301b956008134????4646e2f8c3 }


condition:
	$a0
}