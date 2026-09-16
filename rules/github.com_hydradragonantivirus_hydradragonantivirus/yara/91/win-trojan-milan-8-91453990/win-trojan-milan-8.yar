rule Win_Trojan_Milan_8
{
strings:
	$a0 = { cd2172bf8bd8b80057cd2190909090909090909090 }


condition:
	$a0
}