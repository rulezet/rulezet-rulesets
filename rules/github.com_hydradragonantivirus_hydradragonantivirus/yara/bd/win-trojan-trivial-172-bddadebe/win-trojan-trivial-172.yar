rule Win_Trojan_Trivial_172
{
strings:
	$a0 = { 20ba1c01cd21b8023dba9e00cd2193b440b122ba0001cd21c3 }


condition:
	$a0
}