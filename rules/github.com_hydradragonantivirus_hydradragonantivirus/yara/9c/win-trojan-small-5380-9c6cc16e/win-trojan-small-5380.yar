rule Win_Trojan_Small_5380
{
strings:
	$a0 = { 6061414960616a0041499393810424 }


condition:
	$a0
}