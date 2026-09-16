rule Win_Trojan_Mini_17
{
strings:
	$a0 = { cd21ba694fb44e2af4cd21fe4cfb7235b891d9bae2fbf7eacd2193b43f8bd6b9fffccd213bc1 }


condition:
	$a0
}