rule Win_Trojan_VGEN_442
{
strings:
	$a0 = { cd21737fb43c33c9cd217326b8003d8d96e901cd21736cb43c33c9cd217313b8003d8d960a02cd }


condition:
	$a0
}