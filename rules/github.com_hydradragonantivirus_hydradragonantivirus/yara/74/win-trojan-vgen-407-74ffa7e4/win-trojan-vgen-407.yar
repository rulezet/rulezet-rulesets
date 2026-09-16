rule Win_Trojan_VGEN_407
{
strings:
	$a0 = { c606d807002e8926e0072e8c16de072ec606fd0730b80135cd212e891e02082e8c060408b452cd21268b47fe2ea3d8 }


condition:
	$a0
}