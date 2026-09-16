rule Win_Trojan_DarthVader_4
{
strings:
	$a0 = { 5d81f90f017243b82012cd2f268a }


condition:
	$a0
}