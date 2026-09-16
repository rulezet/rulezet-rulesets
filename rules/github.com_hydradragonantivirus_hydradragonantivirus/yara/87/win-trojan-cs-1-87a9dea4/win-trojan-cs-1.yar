rule Win_Trojan_CS_1
{
strings:
	$a0 = { c904eb01908be0e800005d81ed0c00eb01901e060eeb01901f0eeb019007fc8db6bc03eb01908dbe7a04b90f0090 }


condition:
	$a0
}