rule Win_Trojan_Subsys_12
{
strings:
	$a0 = { 6e8ff335d2e74766bbd205218f748ef3a92866830d90d1c48edbe4fdd754a2ec021a97dcae8e6b5ff397b3ff9af1b107b1796ca9e499d521371b5ba262804f9b }


condition:
	$a0
}