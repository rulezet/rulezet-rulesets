rule Win_Trojan_Ninja_4
{
strings:
	$a0 = { 8b0e2e052e8b163005e80100c39c2eff1e2205c3065033c08ec033c9268a0e6c005807c3e8edff }


condition:
	$a0
}