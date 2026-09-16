rule Win_Trojan_Trivial_158
{
strings:
	$a0 = { 1a01b44ecd21b8013db92000ba9e00cd21938bd6b440cd21c32a2e }


condition:
	$a0
}