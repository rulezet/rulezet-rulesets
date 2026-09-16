rule Win_Trojan_Small_4139
{
strings:
	$a0 = { 680020400068002040006a00e80d0000006a00e800000000ff254c304000 }


condition:
	$a0
}