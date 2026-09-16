rule Win_Trojan_Karbon_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b425ba????cd21baa403cd27b42acd2180fa077522b80102 }


condition:
	$a0
}