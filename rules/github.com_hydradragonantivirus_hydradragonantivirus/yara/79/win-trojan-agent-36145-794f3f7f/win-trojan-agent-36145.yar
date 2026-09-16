rule Win_Trojan_Agent_36145
{
strings:
	$a0 = { 8b051c904000ffd0a351a640002bc62bc36609c003dc2bc503c703c643e88a120000a3f8a040002b3da48541006609db }


condition:
	$a0
}