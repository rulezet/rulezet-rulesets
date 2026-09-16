rule Win_Trojan_Small_4145
{
strings:
	$a0 = { eb01c38d1d99????fd81c36715650289dd8dbb7c070000be3f }


condition:
	$a0
}