rule Win_Trojan_Dicker_1
{
strings:
	$a0 = { 8b1e3c018cc88ed8ba4001b90200b800cd211f813e40014d5a7408813e4001b490750e5f5e1f07 }


condition:
	$a0
}