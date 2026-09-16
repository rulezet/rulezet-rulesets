rule Win_Trojan_Lineage_128
{
strings:
	$a0 = { d42e0b8971a6c5775f803d3569663b90378f7adefddf3fa7666aa479507f3b3bc6d4a839f5601f45b4ea79362476abc40ff5293a6ea819fc3c83a65fd04b7f9e }


condition:
	$a0
}