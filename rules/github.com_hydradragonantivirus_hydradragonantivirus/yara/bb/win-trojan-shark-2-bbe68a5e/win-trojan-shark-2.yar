rule Win_Trojan_Shark_2
{
strings:
	$a0 = { 01534eb440ba0001b903058b1e3401cd21e83afdb440b91c00ba11018b1e3401cd218b0e68 }


condition:
	$a0
}