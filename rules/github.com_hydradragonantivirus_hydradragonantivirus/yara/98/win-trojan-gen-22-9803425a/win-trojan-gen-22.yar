rule Win_Trojan_Gen_22
{
strings:
	$a0 = { b440cd2153558b1481c20301b93405908dbebc068db60801e86a005d5b8d96bc06b440cd21 }


condition:
	$a0
}