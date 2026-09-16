rule Win_Trojan_Small_4041
{
strings:
	$a0 = { bef1??741281def14f3312568dbedc040000e8120000008da888385544192e8d }


condition:
	$a0
}