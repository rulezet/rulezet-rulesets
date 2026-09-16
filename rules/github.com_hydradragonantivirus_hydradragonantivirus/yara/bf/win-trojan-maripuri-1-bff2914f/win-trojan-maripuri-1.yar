rule Win_Trojan_Maripuri_1
{
strings:
	$a0 = { 020000000000003a013c008a1e2b0532c032ff8a24882146fec33ae075f5c3be4b0583c61ee8e3ff8a0e6005b507 }


condition:
	$a0
}