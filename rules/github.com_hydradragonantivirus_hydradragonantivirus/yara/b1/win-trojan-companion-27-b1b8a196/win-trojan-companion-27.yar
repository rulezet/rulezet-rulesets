rule Win_Trojan_Companion_27
{
strings:
	$a0 = { cd21891e57018c065901ba1801b425cd21b28ccd2780fc4b753960061ebf5b00578bf20e07acaa0ac075fab456 }


condition:
	$a0
}