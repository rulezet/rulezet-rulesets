rule Win_Trojan_Small_4366
{
strings:
	$a0 = { b808010070c1c8125050e9??000000 }


condition:
	$a0
}