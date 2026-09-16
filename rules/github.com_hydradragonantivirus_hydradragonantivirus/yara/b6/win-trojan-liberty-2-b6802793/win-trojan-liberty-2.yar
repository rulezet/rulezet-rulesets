rule Win_Trojan_Liberty_2
{
strings:
	$a0 = { 35a02e01cd2183fbff7431b40333dbcd }


condition:
	$a0
}