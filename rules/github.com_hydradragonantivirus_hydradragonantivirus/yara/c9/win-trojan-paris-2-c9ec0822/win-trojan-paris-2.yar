rule Win_Trojan_Paris_2
{
strings:
	$a0 = { d803c38ed88ec08d3e0301b000aaeb }


condition:
	$a0
}