rule Win_Trojan_LTS_1
{
strings:
	$a0 = { 2401b440b9eb0053cd215b5a81c23302b440b9240053 }


condition:
	$a0
}