rule Win_Trojan_Fakealert_82
{
strings:
	$a0 = { e815000000a6340023a500110000e700a54262002900742161d2545f81c70e000000b919 }

	$a1 = { ba6f6f6f74 }


condition:
	$a0 and $a1
}