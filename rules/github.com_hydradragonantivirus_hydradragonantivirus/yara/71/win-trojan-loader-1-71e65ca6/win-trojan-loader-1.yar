rule Win_Trojan_Loader_1
{
strings:
	$a0 = { 8ed8bd0100ba0d00b409cd21803e0c001a7d19b405b500b6008a160c00cd13ba4200b409cd21fe060c00ebe0b0 }


condition:
	$a0
}