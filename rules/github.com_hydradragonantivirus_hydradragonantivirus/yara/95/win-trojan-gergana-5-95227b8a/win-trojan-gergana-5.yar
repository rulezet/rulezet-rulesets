rule Win_Trojan_Gergana_5
{
strings:
	$a0 = { 0150ba80ffb41acd21b92000ba4601b44ecd21727cbadb01b82425cd21ba9effb8023dcd21720d93b9de00ba00fab43fcd217320e80800b44fcd21725473 }


condition:
	$a0
}