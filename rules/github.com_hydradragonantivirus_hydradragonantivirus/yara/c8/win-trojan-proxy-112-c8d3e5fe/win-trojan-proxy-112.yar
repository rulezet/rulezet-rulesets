rule Win_Trojan_Proxy_112
{
strings:
	$a0 = { 558bec83c4f0535657b818222000e8e1f5ffff33c055680c24200064ff3064892085db85c0681c24 }


condition:
	$a0
}