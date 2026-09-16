rule Win_Trojan_Anser_1
{
strings:
	$a0 = { fc021e576a7f9a570a9e00a0c7003a46ff75cdc9c325616e7365722e363534340d0a0d0a0d0a43 }


condition:
	$a0
}