rule Win_Trojan_Packed_106
{
strings:
	$a0 = { 7bb27cbc35727cbc3bf6ccfc7b2e7cbc7eb63bb2ec2bedb0ec29edaeec27edacec25edaaec23eda83bf63c7cec21eda6 }


condition:
	$a0
}