rule Win_Trojan_CCBB_1
{
strings:
	$a0 = { 8edba184008b0e86002e3b0eaf0174272e8a3eb101fec72e883eb1012ea3ad012e890eaf01 }


condition:
	$a0
}