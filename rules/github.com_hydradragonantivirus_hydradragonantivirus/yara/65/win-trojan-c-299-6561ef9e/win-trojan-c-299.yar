rule Win_Trojan_C_299
{
strings:
	$a0 = { 41637469766174696f6e4b6579 }

	$a1 = { 6275696c6465722e657865 }

	$a2 = { 50726f78792e657865 }

	$a3 = { 6275696c6465722e696e69 }


condition:
	$a0 and $a1 and $a2 and $a3
}