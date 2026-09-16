rule Win_Trojan_Taiwan_6
{
strings:
	$a0 = { 950081e1fe00ba9e00cd21b43db002ba }


condition:
	$a0
}