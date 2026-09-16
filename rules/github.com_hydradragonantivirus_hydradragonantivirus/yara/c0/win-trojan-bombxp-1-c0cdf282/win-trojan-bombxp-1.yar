rule Win_Trojan_Bombxp_1
{
strings:
	$a0 = { 736d73626f6d620000000000ffcc3100056f95bbe7724adf4babd30f9f2868e854aa1b68b1730da449b4aedaf375a9409c3a4fad339966cf11b70c00aa0060d3 }


condition:
	$a0
}