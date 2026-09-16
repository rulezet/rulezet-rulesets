rule Win_Trojan_Advent_1
{
strings:
	$a0 = { 8b1e480acd217210b440baae09b902008b1e480acd2173009c8bd78e06a809268e062c00e8c1008cde8ec69d5e5f5a }


condition:
	$a0
}