rule Win_Trojan_Packed_13
{
strings:
	$a0 = { 565058e8 }

	$a1 = { 4607345dd2a3a059 }


condition:
	$a0 and $a1
}