rule Win_Trojan_Vienna_70
{
strings:
	$a0 = { d681eef20189f7b95601fcacfec0aa }


condition:
	$a0
}