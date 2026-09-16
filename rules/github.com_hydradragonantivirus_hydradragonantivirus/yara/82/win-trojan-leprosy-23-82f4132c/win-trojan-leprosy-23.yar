rule Win_Trojan_Leprosy_23
{
strings:
	$a0 = { eb7d900f8b1e8101905390e81500905b90b9e01590ba000190b44090 }


condition:
	$a0
}