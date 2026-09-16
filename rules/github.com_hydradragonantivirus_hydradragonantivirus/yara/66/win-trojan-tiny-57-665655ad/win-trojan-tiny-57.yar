rule Win_Trojan_Tiny_57
{
strings:
	$a0 = { 60ea7724050500a30602b440b9da00ba0002cd21721233c9b8004299cd21b440b90400ba0402cd }


condition:
	$a0
}