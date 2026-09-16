rule Win_Trojan_Trivial_458
{
strings:
	$a0 = { b90000ba5401cd21721eb8023dba9e00cd2193b80040b95a00ba0001cd21b8003ecd21b8004febdeb8004c }


condition:
	$a0
}