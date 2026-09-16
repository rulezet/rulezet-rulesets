rule Win_Trojan_WpcBats_4
{
strings:
	$a0 = { 8198bdfc98a74bae8133849b81c042748285f0d012ac3ae92bfefb970e62013c65e667e31932c8 }


condition:
	$a0
}