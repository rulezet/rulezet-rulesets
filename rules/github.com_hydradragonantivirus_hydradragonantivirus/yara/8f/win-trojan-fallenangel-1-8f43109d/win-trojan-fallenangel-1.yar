rule Win_Trojan_FallenAngel_1
{
strings:
	$a0 = { b91000f7f18ccb03c38ed8b41aba5202cd21ba2402b44ecd217303e9bf00ba7002b8023dcd218bd8e8e0 }


condition:
	$a0
}