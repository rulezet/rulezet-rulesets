rule Win_Trojan_Globe_4
{
strings:
	$a0 = { c2009a0d0040005589e581ec0001c6063f23039a8014c200bfd2001e578dbe00ff165731c0509a9108c2009ad3 }


condition:
	$a0
}