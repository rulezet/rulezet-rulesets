rule Win_Trojan_Trivial_178
{
strings:
	$a0 = { ba1e01cd21b8023dba9e00cd2193ba0001b440b123cd21b43ecd21c3 }


condition:
	$a0
}