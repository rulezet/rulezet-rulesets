rule Win_Trojan_Kaczor_3
{
strings:
	$a0 = { 33c08ed0bc007c501f5007fbcd12c1e0062d8001a32c7c068ec0b80902b90900ba800033dbcd13 }


condition:
	$a0
}