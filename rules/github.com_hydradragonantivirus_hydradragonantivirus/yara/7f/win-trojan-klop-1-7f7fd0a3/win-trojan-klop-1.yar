rule Win_Trojan_Klop_1
{
strings:
	$a0 = { 20286329454d203936b4408b1e0800cd21c3b800428b1e080033c9cd21c3b43f8b1e0800cd }


condition:
	$a0
}