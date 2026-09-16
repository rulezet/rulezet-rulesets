rule Win_Trojan_Vendetta_1
{
strings:
	$a0 = { 04b106d3e02dc0078ec08bf4b900018bfef3a58ec81e078bdc8a161d7cfbe84b01b80102cd13 }


condition:
	$a0
}