rule Win_Trojan_Trivial_331
{
strings:
	$a0 = { 51b44ee9000033c9ba3501cd217221b8023dba9e00cd2193b440b93e00ba0001cd21ba3b01b43bcd2159e2d4b43ecd21 }


condition:
	$a0
}