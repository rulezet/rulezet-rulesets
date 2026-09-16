rule Win_Trojan_Scramble_1
{
strings:
	$a0 = { 4400007403e9a5008d7ea21657bfd9010e579af2053d007503e984008d7ea21657bfdb010e57 }


condition:
	$a0
}