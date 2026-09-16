rule Win_Trojan_Civil_3
{
strings:
	$a0 = { 33c08ed0bc007cb90179ba8000b80e02bb00408ec333dbcd13ea33072040 }


condition:
	$a0
}