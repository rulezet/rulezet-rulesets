rule Win_Trojan_EDS_1
{
strings:
	$a0 = { 013d0101741e0503008bf0fcb90300568bfe8bd68db58e018d3e910103faf3a45eeb0490be0000fcb97f00568dbc }


condition:
	$a0
}