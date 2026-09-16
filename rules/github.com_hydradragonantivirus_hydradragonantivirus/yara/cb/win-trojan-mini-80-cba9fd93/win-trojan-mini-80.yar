rule Win_Trojan_Mini_80
{
strings:
	$a0 = { be0090bf0001ba00feb41acd21ba5801b44eeb06b43ecd21b44f0e1fcd21b91efe722d8bd1b8023dcd218bd7938edeb4 }


condition:
	$a0
}