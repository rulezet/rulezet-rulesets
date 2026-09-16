rule Win_Trojan_Overwrite_1
{
strings:
	$a0 = { 2a00257325735c004558450025632563256325630025 }


condition:
	$a0
}