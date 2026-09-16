rule Win_Trojan_N_22
{
strings:
	$a0 = { e800005e2e807cf7007403e89802b89719cd213d5243744ee8be033d721974468cc0488ec026 }


condition:
	$a0
}