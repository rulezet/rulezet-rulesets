rule Win_Trojan_Wilbur_2
{
strings:
	$a0 = { f6741432e4cd1a8ac28bcef6f132c086e08bf046e8 }


condition:
	$a0
}