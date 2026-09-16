rule Win_Trojan_VCL_27
{
strings:
	$a0 = { b440b903008d95c802cd21b80242998bcacd21b440b95e028d950301cd21b801578b4c168b5418 }


condition:
	$a0
}