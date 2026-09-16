rule Win_Trojan_Banker_6323
{
strings:
	$a0 = { 5061796d656e742e61737078 }

	$a1 = { 6578652e6967636c6b622f }

	$a2 = { 42616e6b6c696e65 }

	$a3 = { 4d5347546578746f38 }


condition:
	$a0 and $a1 and $a2 and $a3
}