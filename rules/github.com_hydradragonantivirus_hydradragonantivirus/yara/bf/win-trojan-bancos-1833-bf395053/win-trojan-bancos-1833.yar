rule Win_Trojan_Bancos_1833
{
strings:
	$a0 = { 733d13522632c5a2ba3d7956bdcb0e62d9451df1e2d7deffe527be1bb48ba8ffeb872149cbc72c1ea5f65c5b624ab3349e5073895e037d3cd18e223cd0ecdf73020a7ef5cda2 }


condition:
	$a0
}