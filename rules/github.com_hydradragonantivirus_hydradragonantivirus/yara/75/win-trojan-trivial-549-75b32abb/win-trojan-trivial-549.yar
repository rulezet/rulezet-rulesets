rule Win_Trojan_Trivial_549
{
strings:
	$a0 = { b8023dba????cd2172??93b440b9[0-3]8bd6cd21b43ecd21b44f }


condition:
	$a0
}