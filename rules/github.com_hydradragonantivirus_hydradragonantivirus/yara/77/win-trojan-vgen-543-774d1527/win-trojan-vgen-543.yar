rule Win_Trojan_VGEN_543
{
strings:
	$a0 = { fe509d58071f5f5e5d5b5a5958cbb448bb0102cd2150b452cd21268b5ffe43588ec0488ed8891e }


condition:
	$a0
}