rule Win_Trojan_Gobleen_1
{
strings:
	$a0 = { cd2180fa0d7522b419cd21b90001faba0000cd26fbb440bb0100b91a008d966a01cd2133c0cd }


condition:
	$a0
}