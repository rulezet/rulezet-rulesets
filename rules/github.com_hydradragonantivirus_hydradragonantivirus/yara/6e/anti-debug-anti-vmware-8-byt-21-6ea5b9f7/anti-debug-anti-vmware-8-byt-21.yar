rule anti_debug__anti_VMWare__8_byt_21_
{
strings:
	$a0 = { b868584d56bb00000000b90a000000ba58560000ed }

condition:
	$a0
}