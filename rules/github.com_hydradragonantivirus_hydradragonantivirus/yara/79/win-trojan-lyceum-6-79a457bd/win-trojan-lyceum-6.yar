rule Win_Trojan_Lyceum_6
{
strings:
	$a0 = { 740f80fc3d740a80fc43740580fc567508e8080075 }


condition:
	$a0
}