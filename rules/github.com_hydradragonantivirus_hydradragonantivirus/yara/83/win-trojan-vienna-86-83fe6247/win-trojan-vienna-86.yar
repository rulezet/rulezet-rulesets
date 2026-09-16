rule Win_Trojan_Vienna_86
{
strings:
	$a0 = { bea72a0e1fe8c200b903005683c60abf0001a5a45e06b42fcd218c4402891c0706b41a8d545fcd211e8b4c }


condition:
	$a0
}