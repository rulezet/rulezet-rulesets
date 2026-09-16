rule Win_Trojan_VGEN_245
{
strings:
	$a0 = { 0301b409cd21be80008a0c32ede35f8bd1468bfefcac57bf2a0251b91f00f2aee309bb1f002bd98a874702595faae2 }


condition:
	$a0
}