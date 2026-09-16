rule Win_Trojan_Bishkek_5
{
strings:
	$a0 = { 02596a329a7b07508007a3b801a1033d0d00740a3d2c422905053d12ed073cc044e833fbeb193d }


condition:
	$a0
}