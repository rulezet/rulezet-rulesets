rule Win_Trojan_Game_1
{
strings:
	$a0 = { 0a2ec70624019090e9ab00fe0e12045052b8024233c949bafdffcd21ba1204b90300b440cd215a }


condition:
	$a0
}