rule Win_Trojan_Patched_114
{
strings:
	$a0 = { e925030000 }

	$a1 = { 55565357e8000000005d81ed47bd40000f20c05025fffffeff0f22c0e827000000899d21ba4000039d1dba4000899d19ba4000e8ccfcffff580f22c08b8519ba40005f5b5e5dffe0 }


condition:
	$a0 and $a1
}