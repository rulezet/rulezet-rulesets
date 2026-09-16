rule Win_Trojan_DarthVader_9
{
strings:
	$a0 = { 2e8b75f826ac3c7574233c9f75ee268b34b9ca008d }


condition:
	$a0
}