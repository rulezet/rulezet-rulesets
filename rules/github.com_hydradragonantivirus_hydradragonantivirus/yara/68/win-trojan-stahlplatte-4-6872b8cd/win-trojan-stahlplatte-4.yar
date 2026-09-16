rule Win_Trojan_Stahlplatte_4
{
strings:
	$a0 = { 7f8ed8be0008bf0000b90001f3a41feb4431 }


condition:
	$a0
}