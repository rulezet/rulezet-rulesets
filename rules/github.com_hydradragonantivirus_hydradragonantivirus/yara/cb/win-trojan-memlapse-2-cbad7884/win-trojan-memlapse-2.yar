rule Win_Trojan_MemLapse_2
{
strings:
	$a0 = { e900002e8b2e0101bfff0047578db64302c605c3ffd7a5a41e068ed88ec0bf0c00be8400a5a5071fb41a8d964a02ccb44e8d96f601b9ff01c686460200cc720deb1280 }


condition:
	$a0
}