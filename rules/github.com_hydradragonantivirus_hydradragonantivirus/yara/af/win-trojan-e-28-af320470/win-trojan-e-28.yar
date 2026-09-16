rule Win_Trojan_E_28
{
strings:
	$a0 = { 8cdd8e062c00b449cd21b40dcd21e82c00bf010033c04faf75fc8d5502892e9701892e9b01892e9f01bb93011e061f07 }


condition:
	$a0
}