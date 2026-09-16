rule Win_Trojan_Explorer_2
{
strings:
	$a0 = { b9fd092e300446fec0e2f8c32ea0dc002ea20e002ec606dc0000bef7012ea0f50b2e2a06f60b }


condition:
	$a0
}