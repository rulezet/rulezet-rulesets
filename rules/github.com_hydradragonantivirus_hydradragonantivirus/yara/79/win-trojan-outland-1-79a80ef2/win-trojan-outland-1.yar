rule Win_Trojan_Outland_1
{
strings:
	$a0 = { 1e8bfe33c0508ed88bc1c4064c002e898444082e8c }


condition:
	$a0
}