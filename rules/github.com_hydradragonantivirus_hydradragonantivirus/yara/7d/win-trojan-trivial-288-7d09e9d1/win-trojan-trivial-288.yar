rule Win_Trojan_Trivial_288
{
strings:
	$a0 = { eb05ba2a01eb04b44eebf7cd21721ab8023dba9e00cd2193b440b12eba0001cd21b43ecd21b44febe2c3 }


condition:
	$a0
}