rule Win_Trojan_SillyC_161
{
strings:
	$a0 = { 019003d6b90300b440cd217220b8024233d233c9cd21b9270190b4408bd6cd21b801578b8c25 }


condition:
	$a0
}