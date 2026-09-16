rule Win_Trojan_VGEN_703
{
strings:
	$a0 = { ba4303cd2133c0cd160c203c79756ab452cd21268b5ffe891e41030e33c08ed8c41e84002e8c0637032e891e3503 }


condition:
	$a0
}