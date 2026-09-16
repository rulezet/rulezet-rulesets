rule Win_Trojan_Vt_1
{
strings:
	$a0 = { d8a1e00040a3e000813ee000102776059a290043009cff1ede215d071f5f5e5a595b }


condition:
	$a0
}