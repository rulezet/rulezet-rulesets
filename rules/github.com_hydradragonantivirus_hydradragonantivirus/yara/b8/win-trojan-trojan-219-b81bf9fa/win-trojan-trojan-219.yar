rule Win_Trojan_Trojan_219
{
strings:
	$a0 = { 8d964d0359cd21b8024233c999cd21b4408d960301b91a02cd21b801578b8e37038b963903 }


condition:
	$a0
}