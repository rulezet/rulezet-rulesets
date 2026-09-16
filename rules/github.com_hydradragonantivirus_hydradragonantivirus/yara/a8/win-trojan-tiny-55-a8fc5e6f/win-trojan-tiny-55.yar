rule Win_Trojan_Tiny_55
{
strings:
	$a0 = { 3e4c004d742bb002e8c4ffc706c7004de92d0400a3c900b4b0b9c30033d2e8b7ff32c0e8a9ffb4 }


condition:
	$a0
}