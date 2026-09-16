rule Win_Trojan_Civil_4
{
strings:
	$a0 = { 33c08ed0bc007cb9c103ba8000b80e02bb00408ec333dbcd13ea82072040 }


condition:
	$a0
}