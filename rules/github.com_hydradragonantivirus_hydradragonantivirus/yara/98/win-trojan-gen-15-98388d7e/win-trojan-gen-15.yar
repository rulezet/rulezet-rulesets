rule Win_Trojan_Gen_15
{
strings:
	$a0 = { 4e018f060a0cba0a0cb90200b80040cd218b16d20bb000ff164e01bafa0bb90400b80040cd21 }


condition:
	$a0
}