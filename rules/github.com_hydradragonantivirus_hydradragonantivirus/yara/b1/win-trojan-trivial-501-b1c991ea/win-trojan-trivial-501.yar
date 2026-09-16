rule Win_Trojan_Trivial_501
{
strings:
	$a0 = { 01cd21e90400b44fcd21b43dba9e00b002cd21a32301b4408b1e2301b9a600ba0001cd21b43e }


condition:
	$a0
}