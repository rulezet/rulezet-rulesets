rule Win_Trojan_Small_4428
{
strings:
	$a0 = { 6a00c704240d3042008d04240f6e100f }


condition:
	$a0
}