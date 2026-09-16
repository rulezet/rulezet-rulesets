rule Win_Trojan_Trivial_295
{
strings:
	$a0 = { 4eba2b01cd2172217306b44fcd217219b8013dba9e00cd2193ba0001b440b93100cd21b43ecd21ebe1c32a2e636f6d }


condition:
	$a0
}