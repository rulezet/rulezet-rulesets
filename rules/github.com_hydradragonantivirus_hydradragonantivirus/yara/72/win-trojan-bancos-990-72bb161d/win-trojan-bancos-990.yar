rule Win_Trojan_Bancos_990
{
strings:
	$a0 = { 9d36ebe72d707512dabe422e31cea6b008abb7ce7fb780e957b22cf175a5ca6b3f16290fa7de7a9a3a822f13ed449b789dbc8f38d4bf002154f8310f9d305c5d }


condition:
	$a0
}