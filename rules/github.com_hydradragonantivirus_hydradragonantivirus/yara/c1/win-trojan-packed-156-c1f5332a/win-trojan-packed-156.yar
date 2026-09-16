rule Win_Trojan_Packed_156
{
strings:
	$a0 = { ff1508304000ff1508304000 }


condition:
	$a0
}