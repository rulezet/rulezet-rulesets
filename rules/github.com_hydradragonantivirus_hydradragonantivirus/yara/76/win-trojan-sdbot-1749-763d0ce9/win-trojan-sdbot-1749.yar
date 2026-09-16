rule Win_Trojan_SdBot_1749
{
strings:
	$a0 = { 750e636b596fa142555348c3996573c569f06e2eee78f3c3d5200c6d6772ab0f8379e7efac6b61737a747f6c6736022eeec77769 }


condition:
	$a0
}