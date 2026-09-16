rule Win_Trojan_Bancos_1816
{
strings:
	$a0 = { 78811cce8ec0b37d3988eeb87cc8475048c1158a9de6e29edbaff9cddfdbc4b9571cdfdad435559006c1a1f80429843bbedb785873f649b8dd8c0d3bf679f3e9c2f583f32a21 }


condition:
	$a0
}