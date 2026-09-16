rule Win_Trojan_Gluck_1
{
strings:
	$a0 = { 019c50535152565755061e1e073d79ff750e1f075d5f5e5a595b58b80f0f9dcf5006b800008ec026c706040000 }


condition:
	$a0
}