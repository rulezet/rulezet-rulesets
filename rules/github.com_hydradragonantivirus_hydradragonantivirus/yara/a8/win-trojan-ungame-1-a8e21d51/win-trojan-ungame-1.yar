rule Win_Trojan_Ungame_1
{
strings:
	$a0 = { cd213dbbbb74651e8cd82d01008ed8bb03008b072d }


condition:
	$a0
}