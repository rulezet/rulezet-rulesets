rule Win_Trojan_V_113
{
strings:
	$a0 = { 2d03008bf08b84ef00a300018b84f100a30201b430cd213c007503e9c800b42fcd21899c3c01b41a8bd681c20c01cd }


condition:
	$a0
}