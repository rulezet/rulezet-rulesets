rule Win_Trojan_Shadow_5
{
strings:
	$a0 = { cd13b405b200cd13b400b003cd10 }


condition:
	$a0
}