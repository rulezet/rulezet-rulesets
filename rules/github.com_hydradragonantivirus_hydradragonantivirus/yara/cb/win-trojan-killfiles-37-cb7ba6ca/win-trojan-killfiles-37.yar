rule Win_Trojan_KillFiles_37
{
strings:
	$a0 = { 524420433a5c202f53202f51 }


condition:
	$a0
}