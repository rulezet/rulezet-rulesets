rule Win_Trojan_Tiny_104
{
strings:
	$a0 = { b8023dcd3272??8bd8b43fb90400ba????8bfa0e1fcd32 }


condition:
	$a0
}