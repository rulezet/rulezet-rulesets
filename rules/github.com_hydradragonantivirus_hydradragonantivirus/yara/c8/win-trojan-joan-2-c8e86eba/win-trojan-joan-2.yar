rule Win_Trojan_Joan_2
{
strings:
	$a0 = { ed748fb41a1f5ae80e00071f5d5f5e5a595b58ea000000009c0ee8f6ffc32a2e73797300 }


condition:
	$a0
}