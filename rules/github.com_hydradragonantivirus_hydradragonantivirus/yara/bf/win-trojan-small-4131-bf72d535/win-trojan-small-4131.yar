rule Win_Trojan_Small_4131
{
strings:
	$a0 = { e82a000000be3fbaa70081f62636f200e80700000075ee50871c24c3 }


condition:
	$a0
}