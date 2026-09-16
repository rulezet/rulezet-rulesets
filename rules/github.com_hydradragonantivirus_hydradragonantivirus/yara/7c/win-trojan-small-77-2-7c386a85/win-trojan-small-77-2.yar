rule Win_Trojan_Small_77_2
{
strings:
	$a0 = { 746e010065736b6d676f00646f74ab6377006c71fbffb7f66c7a6b74af1177736176 }


condition:
	$a0
}