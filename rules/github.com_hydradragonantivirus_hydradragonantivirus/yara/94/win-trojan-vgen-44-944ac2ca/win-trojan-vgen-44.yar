rule Win_Trojan_VGEN_44
{
strings:
	$a0 = { 5d81ed0801b8ad0bcd2181faadde744e8cd8488ed8812e0300ff00812e1200ff00a112008ed82d0f008ec0c606 }


condition:
	$a0
}