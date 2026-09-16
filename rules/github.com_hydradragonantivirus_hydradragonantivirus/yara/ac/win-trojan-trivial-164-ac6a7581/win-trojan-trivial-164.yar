rule Win_Trojan_Trivial_164
{
strings:
	$a0 = { 33c9b44ecd217303e98c00a19a008bd8b10ad3e8d3e02bd8f7db81c3000481fb4c017ee4b8023dba9e00cd2172 }


condition:
	$a0
}