rule Win_Trojan_DM_12
{
strings:
	$a0 = { bf000157a5a531c08ec081c7030126803d06740a81ee7d01e8d6ffe8b8ff0e07c3 }


condition:
	$a0
}