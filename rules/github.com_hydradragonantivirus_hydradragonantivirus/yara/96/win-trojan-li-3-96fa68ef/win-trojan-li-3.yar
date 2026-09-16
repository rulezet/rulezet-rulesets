rule Win_Trojan_Li_3
{
strings:
	$a0 = { e84200b4408b1e0d00b97702ba00002ec7064e02cd21e893002ec7064e029090b43e8b }


condition:
	$a0
}