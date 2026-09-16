rule Win_Trojan_Z_9
{
strings:
	$a0 = { ba2a01e8f5f9eb03e8c0f9071f61c3b43fe8e7f9c3b440e8e1f9c3b80042e8daf9c38bf1e31a }


condition:
	$a0
}