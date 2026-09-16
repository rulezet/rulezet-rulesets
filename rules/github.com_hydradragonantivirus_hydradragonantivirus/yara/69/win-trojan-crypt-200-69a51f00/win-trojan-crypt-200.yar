rule Win_Trojan_Crypt_200
{
strings:
	$a0 = { 81ec04000000892c240f6ee40f7ee5e83ce7ffff68f51b24bf890424ffb528ffffffe8610e00008b8534ff }


condition:
	$a0
}