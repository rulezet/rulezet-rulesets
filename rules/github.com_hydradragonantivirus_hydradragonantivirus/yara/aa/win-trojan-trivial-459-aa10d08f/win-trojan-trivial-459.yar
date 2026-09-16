rule Win_Trojan_Trivial_459
{
strings:
	$a0 = { b90000ba5701cd21721eb8023dba9e00cd2193b80040b95d00ba0001cd21b8003ecd21b8004febde }


condition:
	$a0
}