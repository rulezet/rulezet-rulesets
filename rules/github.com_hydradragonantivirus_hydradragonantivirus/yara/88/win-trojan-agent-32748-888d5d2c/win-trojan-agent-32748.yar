rule Win_Trojan_Agent_32748
{
strings:
	$a0 = { 636f6d6d616e6400636d6400 }

	$a1 = { 203e206e756c002f632064656c }

	$a2 = { 5c77696e737475622e646c6c00 }


condition:
	$a0 and $a1 and $a2
}