rule Win_Trojan_Vundo_424
{
strings:
	$a0 = { 55545d83c4a05333db837d0c015657895df40f8545040000ff750858565252c7042490 }


condition:
	$a0
}