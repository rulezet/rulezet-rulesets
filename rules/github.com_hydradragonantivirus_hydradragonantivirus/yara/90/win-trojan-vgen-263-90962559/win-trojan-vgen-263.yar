rule Win_Trojan_VGEN_263
{
strings:
	$a0 = { 96420359cd21b8024233c999cd21b4408d960001b90f03cd21b801578b8eb7038b96b903 }


condition:
	$a0
}