rule Win_Trojan_Clicker_54
{
strings:
	$a0 = { 616e6e312f6c696e6b732e68746d6c000000000025735c6f7361392e6578650053 }


condition:
	$a0
}