rule Win_Trojan_VGEN_375
{
strings:
	$a0 = { 2bc08ed8a184002ea38003a186002ea38203a1bc002ea38703a1be002ea389031fb8adfee856023d0dd0750633c08e }


condition:
	$a0
}