rule Win_Trojan_BadSector_2
{
strings:
	$a0 = { b430cd21a3????b4dbcd213d00db750ab419cd218ad0b40ecd21 }


condition:
	$a0
}