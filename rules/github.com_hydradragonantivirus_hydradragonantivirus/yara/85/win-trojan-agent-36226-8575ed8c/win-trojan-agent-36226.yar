rule Win_Trojan_Agent_36226
{
strings:
	$a0 = { 643d632e726561642837353029 }

	$a1 = { 69662862213d652626612e[0-32]293d3d226a732229 }


condition:
	$a0 and $a1
}