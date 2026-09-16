rule Win_Trojan_Vundo_455
{
strings:
	$a0 = { 807c2408010f859a0b000060be000006 }

	$a1 = { 6f632e646c6c }


condition:
	$a0 and $a1
}