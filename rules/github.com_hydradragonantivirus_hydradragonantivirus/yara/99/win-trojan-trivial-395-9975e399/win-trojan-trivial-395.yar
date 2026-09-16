rule Win_Trojan_Trivial_395
{
strings:
	$a0 = { 023dba9e00cd218bd8b440b97400ba0001cd21b43ecd21b44febddb802fa50b300ba455952cd16 }


condition:
	$a0
}