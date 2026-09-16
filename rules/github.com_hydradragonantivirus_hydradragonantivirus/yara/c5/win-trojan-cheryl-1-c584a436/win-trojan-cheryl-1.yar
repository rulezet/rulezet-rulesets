rule Win_Trojan_Cheryl_1
{
strings:
	$a0 = { 5b43686572796c5d005b4a65726b314e2f444946465553494f4e5d00000000002a2e54585400ad6da4db2aeb287f }


condition:
	$a0
}