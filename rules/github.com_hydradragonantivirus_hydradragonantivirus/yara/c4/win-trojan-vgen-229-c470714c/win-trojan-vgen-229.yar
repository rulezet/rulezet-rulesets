rule Win_Trojan_VGEN_229
{
strings:
	$a0 = { c9e89100b002e88200b4408d965a0459cd21b8024233c999cd21b42ccd210bd274f889960901 }


condition:
	$a0
}