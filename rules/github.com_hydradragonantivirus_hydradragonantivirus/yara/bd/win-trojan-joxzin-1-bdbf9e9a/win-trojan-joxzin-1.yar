rule Win_Trojan_Joxzin_1
{
strings:
	$a0 = { 010400550002000000ffffa51200005505000006000000a512 }


condition:
	$a0
}