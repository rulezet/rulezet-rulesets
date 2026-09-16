rule Win_Trojan_Msr_1
{
strings:
	$a0 = { f4f591ee9cf1b8b4bcbb91e892f275f0920075f0920275f0f3f3f3fb9ff7c7c5eb919291759ff48b919291759ff48b91a1919cfdb480819a908d909691efee }


condition:
	$a0
}