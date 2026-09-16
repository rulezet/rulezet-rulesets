rule Win_Trojan_Small_4434
{
strings:
	$a0 = { b8010100d8e9 }

	$a1 = { c1c812508d5c2000 }


condition:
	$a0 and $a1
}