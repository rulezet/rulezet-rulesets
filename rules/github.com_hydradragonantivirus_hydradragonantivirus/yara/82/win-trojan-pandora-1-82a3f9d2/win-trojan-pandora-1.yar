rule Win_Trojan_Pandora_1
{
strings:
	$a0 = { b431cd21b404cd1a80fe03751f80fa12751ab80091cd103d00917505ba5a02eb03ba3303b4 }


condition:
	$a0
}