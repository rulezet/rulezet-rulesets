rule Win_Trojan_VB_1091
{
strings:
	$a0 = { 636d64436f6e6e656374 }

	$a1 = { 7478744950 }

	$a2 = { 747874536179 }

	$a3 = { 43006f006e006e00650063007400650064 }


condition:
	$a0 and $a1 and $a2 and $a3
}